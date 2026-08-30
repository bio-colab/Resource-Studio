from core.rc_format import compile_rc, decompile_res


RC = '''STRINGTABLE
BEGIN
  1 "Hello"
  17 "World"
END

IDR_MENU MENU
BEGIN
  MENUITEM "Open", 100
  POPUP "File"
  BEGIN
    MENUITEM SEPARATOR
    MENUITEM "Exit", 101
  END
END
'''


def main() -> None:
    compiled = compile_rc(RC).to_bytes()
    assert compiled
    decompiled = decompile_res(compiled)
    assert '1 "Hello"' in decompiled
    assert '17 "World"' in decompiled
    assert 'IDR_MENU MENU' in decompiled
    assert compile_rc(decompiled).to_bytes() == compiled
    print("rc-format-tests: passed")


if __name__ == "__main__":
    main()
