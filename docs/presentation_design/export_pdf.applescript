on run argv
    set inputFile to POSIX file (item 1 of argv)
    set outputFile to POSIX file (item 2 of argv)
    tell application "Microsoft PowerPoint"
        open inputFile
        set deck to active presentation
        save deck in outputFile as save as PDF
        close deck saving no
    end tell
end run
