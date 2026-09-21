import Foundation
import AppKit
import CoreText

// FreeType cannot read this template title font's Hangul glyphs. CoreText can.
let output = URL(fileURLWithPath: CommandLine.arguments[1])
let scale = 1.875
let fontURL = URL(fileURLWithPath: NSHomeDirectory() + "/Library/Fonts/210Omnigothic.ttf")
CTFontManagerRegisterFontsForURL(fontURL as CFURL, .process, nil)
let font = CTFontCreateWithName("210 옴니고딕" as CFString, 35.01 * scale, nil)
let titles: [(Int, String)] = CommandLine.arguments.count > 2
    ? Array(CommandLine.arguments.dropFirst(2)).enumerated().map { ($0.offset + 2, $0.element) }
    : [(2, "시스원 업무 활용"), (4, "제공물과 적용 조건")]
for (page, title) in titles {
    let width = 680, height = 100
    let ctx = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8,
        bytesPerRow: width * 4, space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let attributed = NSAttributedString(string: title, attributes: [
        .font: font, .kern: -0.70 * scale,
        .foregroundColor: NSColor(srgbRed: 0.2, green: 0.2, blue: 0.2, alpha: 1)])
    let line = CTLineCreateWithAttributedString(attributed)
    ctx.textPosition = CGPoint(x: 0, y: Double(height) - CTFontGetAscent(font))
    CTLineDraw(line, ctx)
    let bitmap = NSBitmapImageRep(cgImage: ctx.makeImage()!)
    try bitmap.representation(using: .png, properties: [:])!.write(
        to: output.appendingPathComponent("native-title-\(page).png"))
    print(page, CTFontCopyPostScriptName(font), CTLineGetTypographicBounds(line,nil,nil,nil))
}
