import option


def main():
    parser = option.init_argparse()
    if hasattr(parser, 'parse_intermixed_args'):
        options = parser.parse_intermixed_args()
    else:
        options = parser.parse_args()
    option.option(options)


if __name__ == '__main__':
    main()