# VHS tape script for 20-second terminal demo GIF
# Requirements: vhs (https://github.com/charmbracelet/vhs)

Output demo/demo.gif

Set FontSize 16
Set Width 1200
Set Height 600
Set Padding 20
Set Theme "Catppuccin Macchiato"

Type "git status"
Enter
Sleep 1.5s

Type "git add ."
Enter
Sleep 1s

Type "npx @lazycoder11/env-scanner"
Enter
Sleep 4s

Type "# 🚨 Accidental secret commit caught before push!"
Enter
Sleep 2s
