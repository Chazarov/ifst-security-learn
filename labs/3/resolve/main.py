from core import create_rsa
from preview import run_app


def main() -> None:
    crypto = create_rsa()
    run_app(crypto)


if __name__ == "__main__":
    main()
