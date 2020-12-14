import Foundation

struct UnderlyingError: Codable {
	let code: Int
	let domain: String
	let userInfo: [String: String]

	init(_ error: NSError) {
		self.code = error.code
		self.domain = error.domain

		let extracted: [String] = [
		//	"_kCFStreamErrorCodeKey",
		//	"_kCFStreamErrorDomainKey"
		]

		var userInfo: [String: String] = [:]
		for (key, value) in error.userInfo {
			if extracted.contains(key) { continue }
			userInfo[key] = "\(value)"
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
	let failingUrl: String?
	let underlyingError: UnderlyingError?
	let userInfo: [String: String]

	init(_ error: URLError) {
		self.code = error.errorCode
		self.failingUrl = error.failureURLString
		self.underlyingError = error.underlyingError

		let extracted: [String] = [
		//	"_kCFStreamErrorCodeKey",
		//	"_kCFStreamErrorDomainKey",
		//	"NSErrorFailingURLKey",
		//	"NSErrorFailingURLStringKey",
			"NSUnderlyingError"
		]

		var userInfo: [String: String] = [:]
		for (key, value) in error.userInfo {
			if extracted.contains(key) { continue }
			userInfo[key] = "\(value)"
		}
		self.userInfo = userInfo
	}
}

struct ATSResult: Codable {
	let url: URL
	let redirectedUrl: URL?
	let error: ATSError?
	let timestamp: String

	init(url: URL, redirectedUrl: URL?, error: ATSError?, date: Date = Date()) {
		self.url = url
		self.redirectedUrl = redirectedUrl != url ? redirectedUrl : nil
		self.error = error
		self.timestamp = ISO8601DateFormatter().string(from: date)
	}
}

struct CommonError: Codable {
	let url: URL
	let error: String
	let timestamp: String

	init(url: URL, error: Error, date: Date = Date()) {
		self.url = url
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

func main() -> ExitCode {
	let printContentOpt = "--print-content"
	let printContent = CommandLine.arguments.contains(printContentOpt)

	var requiredArgs = 1
	if printContent { requiredArgs += 1 }

	guard requiredArgs < CommandLine.arguments.count else {
		echo("Usage: \(CommandLine.arguments[0]) [\(printContentOpt)] URL...", err: true)
		return .failure
	}

	var urls: Set<URL> = []
	for argument in CommandLine.arguments[1...] {
		guard argument != printContentOpt else { continue }
		guard let url = URL(string: argument) else {
			echo("Invalid URL: \(argument)", err: true)
			return .failure
		}
		urls.insert(url)
	}

	// Theoretically setting the initial value of the `mainSemaphore` to
	// `-urls.count` should work. However, this leads to a segmentation fault.
	// Hence, an additional counter is used to achieve the same.
	// The `mainSemaphore` is required to wait for all tasks to finish, before
	// exiting the process (and terminating the ongoing tasks).
	let mainSemaphore = DispatchSemaphore(value: 0)
	var counter = urls.count

	// The `outputSemaphore` is used to determine the number of concurrent HTTP
	// requests.
	let concurrentTasks = 8
	let outputSemaphore = DispatchSemaphore(value: concurrentTasks)

	let session = URLSession(configuration: .ephemeral)

	let encoder = JSONEncoder()
	var exitCode: ExitCode = .success

	for url in urls {
		let task = session.dataTask(with: url) { optionalData, optionalResponse, optionalError in

			// Lock output in order to avoid it being garbled.
			outputSemaphore.wait()

			// Write output
			do {
				if let error = optionalError as? URLError {
					let result = ATSResult(url: url, redirectedUrl: optionalResponse?.url, error: ATSError(error))
					echo(try encoder.encode(result))
				} else if let error = optionalError {
					let result = CommonError(url: url, error: error)
					echo(try encoder.encode(result))
				} else {
					let result = ATSResult(url: url, redirectedUrl: optionalResponse?.url, error: nil)
					echo(try encoder.encode(result))
					if printContent {
						echo(optionalData!)
					}
				}
			} catch {
				echo("Failed to encode result for URL '\(url)': \(error.localizedDescription)", err: true)
				exitCode = .failure
			}

			 // Release locked output
			outputSemaphore.signal()

			// Mark task as finished
			counter -= 1
			mainSemaphore.signal()
		}
		task.resume()
	}

	// Wait until all tasks are finished
	while 0 < counter { mainSemaphore.wait() }

	return exitCode
}

exit(main().rawValue)
