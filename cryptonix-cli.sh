#!/bin/bash

RED="\e[1;31m"       # Bold Red for Security Alerts
CYAN="\e[38;5;51m"    # Electric Cyan for Frame/Logo
AMBER="\e[38;5;214m"  # Amber for Selection Menu
WHITE="\e[1;37m"     # Pure White for Options
RESET="\e[0m"
BOLD="\e[1m"

clear
echo -e "${CYAN}${BOLD}"
    echo " ╔══════════════════════════════════════════════════════════════════════════╗"
    echo " ║  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗ ║"
    echo " ║ ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║██║╚██╗██╔╝ ║"
    echo " ║ ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██╔██╗ ██║██║ ╚███╔╝  ║"
    echo " ║ ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║╚██╗██║██║ ██╔██╗  ║"
    echo " ║ ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║ ╚████║██║██╔╝ ██╗ ║"
    echo " ║  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝ ║"
    echo " ╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "               ${PURPLE}v2.5 - Professional Encryption Suite${RESET}"
    echo ""
echo -e "${RESET}"

while true; do
echo -e "${WHITE}${BOLD}  OPERATIONS CONTROL"
echo -e " ${CYAN}──────────────────────────────────────────"
echo -e " ${CYAN}[1] ${BOLD}Encrypt Interface"
echo -e " ${CYAN}[2] ${BOLD}Decrypt Interface"
echo -e " ${CYAN}[3] Algorithm Information"
echo -e " ${CYAN}[4] Exit"
echo -e " ${CYAN}------------------------------------------"
echo -e "${RESET}"
read -p "$(echo -e "${AMBER}${BOLD}Select option » ")" opt

# ... (Keep the top banner and while loop as is)

case $opt in
1)
    echo -e "\n${CYAN}${BOLD}TARGET SELECTION:"
    echo -e "${WHITE}1. Text"
    echo -e "${WHITE}2. File"
    read -p "Choose: " enc

    if [ "$enc" == "1" ]; then
        python3 cryptonix.py encrypt_text
    # ... [Inside your case statement for Encrypt] ...
    elif [ "$enc" == "2" ]; then
        # Use Zenity to pick the file
        FILE=$(zenity --file-selection --title="Select file to encrypt" 2>/dev/null)

        # If user didn't cancel, pass the file to your python script
        if [ ! -z "$FILE" ]; then
            python3 cryptonix.py encrypt_file "$FILE"
        fi
    fi
;;
2)
    echo -e "\n${CYAN}${BOLD}TARGET SELECTION:"
    echo -e "${WHITE}1. Text"
    echo -e "${WHITE}2. File"
    read -p "Choose: " dec

    if [ "$dec" == "1" ]; then
        python3 cryptonix.py decrypt_text
    elif [ "$dec" == "2" ]; then
        FILE=$(zenity --file-selection --title="Select encrypted file" 2>/dev/null)
        
        if [ ! -z "$FILE" ]; then
            python3 cryptonix.py decrypt_file "$FILE"
        fi
    fi
;;

3)
    python3 cli.py info
;;

4)
    echo -e "${GREEN}Goodbye!${RESET}"
    exit
;;
*)
    echo -e "${RED}Invalid option${RESET}"
;;
esac
done
