import Foundation
import Network

struct Endpoint: Hashable, Codable {
	let usesTls: Bool
	let host: String
	let port: UInt16

	init?(usesTls: Bool, host: String, port: UInt16) {
		guard 0 < port else { return nil }

		self.usesTls = usesTls
		self.host = host
		self.port = port
	}

	init?(url: URL) {
		guard let host = url.host?.lowercased() else { return nil }

		guard let scheme = url.scheme?.lowercased() else { return nil }
		guard ["http", "https"].contains(scheme) else { return nil }
		let usesTls = scheme == "https"

		let port: UInt16
		if let givenPort = url.port {
			let requiredBits = givenPort.bitWidth - givenPort.leadingZeroBitCount
			guard requiredBits <= 16 else { return nil }
			port = UInt16(givenPort)
		} else {
			port = usesTls ? 443 : 80
		}

		self.init(usesTls: usesTls, host: host, port: port)
	}

	init?(string: String) {
		guard let url = URL(string: string) else { return nil }
		self.init(url: url)
	}

	var url: URL {
		let scheme = usesTls ? "https" : "http"
		let netloc: String
		if (!usesTls && port == 80) || (usesTls && port == 443) {
			netloc = host
		} else {
			netloc = "\(host):\(port)"
		}
		return URL(string: "\(scheme)://\(netloc)/")!
	}

}

extension Endpoint: CustomStringConvertible {

	var description: String {
		return url.absoluteString
	}

}

extension URLSessionTask {

	var originalEndpoint: Endpoint {
		let originalRequest = self.originalRequest!
		let originalUrl = originalRequest.url!
		return Endpoint(url: originalUrl)!
	}

	var currentEndpoint: Endpoint? {
		guard let currentUrl = currentRequest?.url else { return nil }
		return Endpoint(url: currentUrl)!
	}

}

struct UnderlyingError: Codable {
	let code: Int
	let streamErrorCode: Int?
	let domain: String
	let userInfo: [String: String]

	init(_ error: NSError) {
		self.code = error.code
		self.domain = error.domain

		if error.userInfo.contains(where: {$0.key == "_kCFStreamErrorCodeKey"}) {
			self.streamErrorCode = error.userInfo["_kCFStreamErrorCodeKey"] as? Int
		} else {
			self.streamErrorCode = nil
		}

		let extracted: [String] = [
			"_kCFStreamErrorCodeKey"
		//	"_kCFStreamErrorDomainKey"
		]

		var userInfo: [String: String] = [:]
		for (key, value) in error.userInfo {
			if extracted.contains(key) { continue }
			if let data = value as? Data {
				/*
				if key == "NSErrorPeerAddressKey" {
					if 16 <= data.count {
						let rawAddress = data[0..<16]
						if let last = rawAddress.lastIndex(where: {$0 != 0}) {
							if last > 4, let address = IPv6Address(data[0..<16], nil) {
								userInfo[key] = String(describing: address)
								continue
							}
							if 4 <= data.count, let address = IPv4Address(data[0..<4], nil) {
								userInfo[key] = String(describing: address)
								continue
							}
						}
					}
				}
				*/
				userInfo[key] = "base64:" + data.base64EncodedString()
			} else {
				userInfo[key] = String(describing: value)
			}
		}
		self.userInfo = userInfo
	}
}

extension URLError {
	var underlyingError: UnderlyingError? {
		guard let error = self.userInfo["NSUnderlyingError"] as? NSError else {
			return nil
		}
		return UnderlyingError(error)
	}
}

struct ATSError: Codable {
	let code: Int
	let streamErrorCode: Int?
	//let failingUrl: String?
	let underlyingError: UnderlyingError?
	let userInfo: [String: String]

	init(_ error: URLError) {
		self.code = error.errorCode
		//self.failingUrl = error.failureURLString
		self.underlyingError = error.underlyingError

		if error.userInfo.contains(where: {$0.key == "_kCFStreamErrorCodeKey"}) {
			self.streamErrorCode = error.userInfo["_kCFStreamErrorCodeKey"] as? Int
		} else {
			self.streamErrorCode = nil
		}

		let extracted: [String] = [
			"_kCFStreamErrorCodeKey",
		//	"_kCFStreamErrorDomainKey",
			"_NSURLErrorFailingURLSessionTaskErrorKey",
			"_NSURLErrorRelatedURLSessionTaskErrorKey",
			"NSErrorFailingURLKey",
			"NSErrorFailingURLStringKey",
			"NSUnderlyingError"
		]

		var userInfo: [String: String] = [:]
		for (key, value) in error.userInfo {
			if extracted.contains(key) { continue }
			userInfo[key] = String(describing: value)
		}
		self.userInfo = userInfo
	}
}

struct ATSResult: Codable {
	let url: URL
	let redirectedUrl: URL?
	let error: ATSError?
	let timestamp: String

	init(endpoint: Endpoint, redirectedEndpoint: Endpoint? = nil, error: ATSError? = nil, date: Date = Date()) {
		self.url = endpoint.url
		self.redirectedUrl = redirectedEndpoint != endpoint ? redirectedEndpoint?.url : nil
		self.error = error
		self.timestamp = ISO8601DateFormatter().string(from: date)
	}
}

struct CommonError: Codable {
	let url: URL
	let error: String
	let timestamp: String

	init(endpoint: Endpoint, error: Error, date: Date = Date()) {
		self.url = endpoint.url
		self.error = error.localizedDescription
		self.timestamp = ISO8601DateFormatter().string(from: date)
	}
}

enum ExitCode: Int32 {
	case success = 0
	case failure = 1
}

func echo(_ data: Data, err: Bool = false, end optionalEnd: Data? = Data("\n".utf8)) {
	let handle = err ? FileHandle.standardError : FileHandle.standardOutput
	handle.write(data)
	if let end = optionalEnd {
		handle.write(end)
	}
}

func echo(_ text: String, err: Bool = false, end: String? = "\n") {
	echo(Data(text.utf8), err: err, end: (end == nil ? nil : Data(end!.utf8)))
}

//func debug(_ text: String, end: String? = "\n") {
//	echo(text, err: true, end: end)
//}

struct State {
	let pending: Set<Endpoint>
	let finished: Set<Endpoint>
	let redirections: [Endpoint: Endpoint]
	let success: Bool

	var endpoints: Set<Endpoint> {
		return pending.union(finished)
	}

	init(pending: Set<Endpoint> = [], finished: Set<Endpoint> = [], redirections: [Endpoint: Endpoint] = [:], success: Bool = true) {
		self.pending = pending
		self.finished = finished
		self.redirections = redirections
		self.success = success
	}

	func with(new endpoint: Endpoint) -> State {
		precondition(!finished.contains(endpoint))

		let pending = self.pending.union([endpoint])
		return State(pending: pending, finished: finished, redirections: redirections, success: success)
	}

	func with(finished endpoint: Endpoint) -> State {
		precondition(pending.contains(endpoint))

		let pending = self.pending.subtracting([endpoint])
		return State(pending: pending, finished: finished, redirections: redirections, success: success)
	}

	func with(endpoint: Endpoint, redirectingTo redirectionEndpoint: Endpoint) -> State {
		precondition(endpoints.contains(endpoint))
		precondition(!redirections.contains(where: { $0.key == endpoint }))

		let redirections = self.redirections.merging([endpoint: redirectionEndpoint], uniquingKeysWith: { $1 })
		return State(pending: pending, finished: finished, redirections: redirections, success: success)
	}

	var failing: State {
		return State(pending: pending, finished: finished, redirections: redirections, success: false)
	}
}

class Application: NSObject {
	let followRedirects: Bool

	var state: State
	let stateSemaphore: DispatchSemaphore

	let encoder: JSONEncoder
	let outputSemaphore: DispatchSemaphore

	/**
	The `taskSemaphore` is required to wait for all tasks to finish, before
	exiting the process (and terminating pending tasks).
	*/
	let taskSemaphore: DispatchSemaphore

	init(followRedirects: Bool, concurrentTasks: Int = 4) {
		self.followRedirects = followRedirects
		self.state = State()
		self.stateSemaphore = DispatchSemaphore(value: concurrentTasks)
		self.encoder = JSONEncoder()
		self.outputSemaphore = DispatchSemaphore(value: concurrentTasks)

		/*
		Theoretically setting the initial value of the `taskSemaphore` to
		the number of URLs should work. However, this leads to a segmentation
		fault. Consequently, manual bookkeeping of unprocessed tasks through
		`pending` is performed to achieve the same. In addition, this allows to
		avoid performing multiple probes of the same endpoint.
		*/
		self.taskSemaphore = DispatchSemaphore(value: 0)
	}

	var hasPendingTasks: Bool {
		stateSemaphore.wait()
		let result = !state.pending.isEmpty
		stateSemaphore.signal()
		return result
	}

	func probe(endpoints: Set<Endpoint>) -> ExitCode {
		precondition(!hasPendingTasks)

		state = State()

		for endpoint in endpoints {
			startTask(with: endpoint)
		}

		// Wait until all tasks are finished
		while hasPendingTasks { taskSemaphore.wait() }

		// No concurrent tasks anymore, state can be accessed at will
		return state.success ? .success : .failure
	}

	// MARK: Convenience state accessors/modifiers
	// Call these functions with `stateSemaphore` being locked in order to avoid
	// race conditions of concurrent tasks.

	func startTask(with endpoint: Endpoint) {
		/*
		Do not probe endpoints that are either currently pending or have been
		finished already.
		*/
		guard !state.endpoints.contains(endpoint) else {
			return
		}

		let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
		let task = session.dataTask(with: endpoint.url)

		state = state.with(new: endpoint)

		task.resume()
	}

	func finish(task: URLSessionDataTask) {
		state = state.with(finished: task.originalEndpoint)
		taskSemaphore.signal()
	}

	func finish(task: URLSessionTask) {
		let dataTask = task as! URLSessionDataTask
		finish(task: dataTask)
	}

	func output<T>(_ value: T, for endpoint: Endpoint) where T: Encodable {
		outputSemaphore.wait()
		do {
			echo(try encoder.encode(value))
		} catch {
			echo("Failed to encode result for endpoint '\(endpoint)': \(error.localizedDescription)", err: true)
			state = state.failing
		}
		outputSemaphore.signal()
	}

	func redirectedEndpoint(of task: URLSessionTask) -> Endpoint? {
		let originalEndpoint = task.originalEndpoint
		let currentEndpoint = task.currentEndpoint

		let result: Endpoint?
		if (currentEndpoint == nil || currentEndpoint == originalEndpoint) && state.redirections.contains(where: { $0.key == originalEndpoint }) {
			result = state.redirections[originalEndpoint]
		} else {
			result = currentEndpoint
		}

		return result
	}

}

extension Application: URLSessionDataDelegate {

	// MARK: URLSessionDataDelegate

	func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
		assert(dataTask.currentRequest?.url == response.url)

		// Connection did succeed

		stateSemaphore.wait()

		let originalEndpoint = dataTask.originalEndpoint
		let redirectedEndpoint = self.redirectedEndpoint(of: dataTask)

		let result = ATSResult(endpoint: originalEndpoint, redirectedEndpoint: redirectedEndpoint)
		output(result, for: originalEndpoint)

		finish(task: dataTask)

		stateSemaphore.signal()

		completionHandler(.cancel)
	}

	// MARK: URLSessionTaskDelegate

	func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
		/*
		Connection might have failed or might have succeeded with an
		application-level error.
		*/

		stateSemaphore.wait()

		let originalEndpoint = task.originalEndpoint
		let redirectedEndpoint = self.redirectedEndpoint(of: task)

		guard let error = error else {
			// TODO: Can this occur?
			fatalError("Unknown error")
		}

		guard let urlError = error as? URLError else {
			let result = CommonError(endpoint: originalEndpoint, error: error)
			output(result, for: originalEndpoint)

			finish(task: task)

			stateSemaphore.signal()
			return
		}

		let result: ATSResult
		switch urlError.code {
			case .cannotParseResponse: fallthrough
			case .userCancelledAuthentication:
				/*
				Application-level error that is reported after the connection
				was established successfully. Hence, this error is ignored while
				probing ATS.
				*/
				result = ATSResult(endpoint: originalEndpoint, redirectedEndpoint: redirectedEndpoint)
			case .cancelled:
				/*
				This occurs, if a HTTP redirect was cancelled. The results have
				been reported and task was already marked as finished.
				TODO: Are there any other reasons?
				*/
				let dataTask = task as! URLSessionDataTask
				assert(!state.endpoints.contains(dataTask.originalEndpoint))
				stateSemaphore.signal()
				return
			default:
				result = ATSResult(endpoint: originalEndpoint, redirectedEndpoint: redirectedEndpoint, error: ATSError(urlError))
		}

		output(result, for: originalEndpoint)
		finish(task: task)

		stateSemaphore.signal()
		return
	}

	func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
					completionHandler: @escaping (URLRequest?) -> Void) {
		// Connection to the initially requested URL did succeed.

		stateSemaphore.wait()

		let originalEndpoint = task.originalEndpoint
		let redirectedUrl = request.url!
		let redirectedEndpoint = Endpoint(url: redirectedUrl)!

		echo("HTTP Redirection: \(originalEndpoint) -> \(redirectedEndpoint)", err: true)

		// Keep track of redirections, so that they can be reported later.
		state = state.with(endpoint: originalEndpoint, redirectingTo: redirectedEndpoint)

		/*
		Cancel redirection in order to manually handle the new request. Note
		that this will complete the task and lead to the delegate
		`urlSession(_:dataTask:didReceive:completionHandler:)` being called with
		the HTTP response requesting the redirect. Hence, the task must not be
		marked as completed here and results must not be reported, else they
		will be reported twice.
		*/
		completionHandler(nil)

		/*
		If the host/domain of the redirected URL is the same as for the
		originally requested URL, only another resource of the same remote
		target is accessed and hence, connection should succeed as well.
		If the hosts/domains do not match, it might not make sense to probe the
		redirection target, as it was originally unknown and there is probably
		no exception domain added to the ATS configuration.

		In case of using the default configuration or if ATS is disabled, this
		might provide useful information anyway. The caller has to handle the
		results appropriately, as this prober cannot manually modify the ATS
		configuration, as it does not possess the
		`com.apple.private.nsurlsession.impersonate` entitlement.
		TODO: Maybe it is possible to preload a dynamic library to `nscurl`?
		*/
		if followRedirects {
			startTask(with: redirectedEndpoint)
		}

		stateSemaphore.signal()
	}

}

func main() -> ExitCode {
	let followRedirectsOpt = "--follow-redirects"
	let followRedirects = CommandLine.arguments.contains(followRedirectsOpt)

	var requiredArguments = 1
	if followRedirects { requiredArguments += 1 }

	guard requiredArguments < CommandLine.arguments.count else {
		echo("Usage: \(CommandLine.arguments[0]) [\(followRedirectsOpt)] URL...", err: true)
		return .failure
	}

	var endpoints: Set<Endpoint> = []
	for argument in CommandLine.arguments[1...] {
		guard argument != followRedirectsOpt else { continue }
		guard let endpoint = Endpoint(string: argument) else {
			echo("Invalid URL: \(argument)", err: true)
			return .failure
		}
		endpoints.insert(endpoint)
	}

	let app = Application(followRedirects: followRedirects)
	return app.probe(endpoints: endpoints)
}

exit(main().rawValue)
