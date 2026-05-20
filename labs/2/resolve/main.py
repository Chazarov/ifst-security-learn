from core import KeyStore
from preview import run_app


def main() -> None:
    store = KeyStore.create()
    run_app(store)


if __name__ == "__main__":
    main()
