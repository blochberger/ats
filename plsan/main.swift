import Foundation

let data = FileHandle.standardInput.readDataToEndOfFile()

let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)

let xml = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)

FileHandle.standardOutput.write(xml)
