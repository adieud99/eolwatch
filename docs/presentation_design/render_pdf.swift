import Foundation
import AppKit
import PDFKit

let input = URL(fileURLWithPath: CommandLine.arguments[1])
let destination = URL(fileURLWithPath: CommandLine.arguments[2])
try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
guard let document = PDFDocument(url: input) else { fatalError("Cannot open PDF") }
for index in 0..<document.pageCount {
    let page = document.page(at: index)!
    let size = page.bounds(for: .mediaBox).size
    let scale = 1800.0 / size.width
    let target = NSSize(width: 1800, height: size.height * scale)
    let img = page.thumbnail(of: target, for: .mediaBox)
    let bitmap = NSBitmapImageRep(data: img.tiffRepresentation!)!
    let output = destination.appendingPathComponent("slide-\(index + 1).png")
    try bitmap.representation(using: .png, properties: [:])!.write(to: output)
    print(output.path)
}
