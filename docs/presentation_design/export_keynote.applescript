on run argv
    set inputFile to POSIX file (item 1 of argv)
    set outputFile to POSIX file (item 2 of argv)
    tell application "Keynote"
        set deck to open inputFile
        export deck to outputFile as PDF with properties {PDF image quality:Best, export style:IndividualSlides, all stages:false, borders:false, slide numbers:false, date:false}
        close deck saving no
    end tell
end run
