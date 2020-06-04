import argparse

from response_analyzer import ResponseParser


def main():
    args = get_args()

    print('VulnHunter\nA simple but effective penetration testing program\n\n')

    response_headers_parser = ResponseParser(args.url)


def get_args():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-u', '--url', dest='url', help='Site URL', required=True)
    arg_parser.add_argument('-m', '--mode', dest='mode', help='Scan mode', default=1, type=int)

    return arg_parser.parse_args()


if __name__ == '__main__':
    main()
