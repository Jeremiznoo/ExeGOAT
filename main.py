import argparse
from colorama import init, Fore, Style

def main():
    init(autoreset=True)

    BLUE = Fore.BLUE
    WHITE = Fore.WHITE
    RED = Fore.RED
    GREEN = Fore.GREEN
    RESET = Style.RESET_ALL

    BANNER = rf"""
{BLUE}___________ {WHITE}         {RED}        {GREEN}  ________  ________       _____    ___________{RESET}
{BLUE}\_   _____/ {WHITE}___  ___ {RED}  ____  {GREEN} /  _____/  \_____  \     /  _  \   \__    ___/{RESET}
{BLUE} |    __)_  {WHITE}\  \/  / {RED}_/ __ \ {GREEN}/   \  ___   /   |   \   /  /_\  \    |    |   {RESET}
{BLUE} |        \ {WHITE} >    <  {RED}\  ___/ {GREEN}\    \_\  \ /    |    \ /    |    \   |    |   {RESET}
{BLUE}/_______  / {WHITE}/__/\_ \ {RED} \___  >{GREEN} \______  / \_______  / \____|__  /   |____|   {RESET}
{BLUE}        \/  {WHITE}      \/ {RED}     \/ {GREEN}        \/          \/          \/             {RESET}"""

    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="ExeGOAT",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    args = parser.parse_args()

    parser.print_help()


if __name__ == "__main__":
    main()
