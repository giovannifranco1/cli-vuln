from pathlib import Path
from cli_vuln.core.security import scanning_utils
from cli_vuln.vulnerabilities.xss import Xss


def it_should_execute_path_scan_xss_on_php_file_and_return_result():
    """
    Test scan function with a PHP file.
    """

    factory_path = Path("tests/feature/test_php/test.php")
    factory_path.parent.mkdir(parents=True, exist_ok=True)
    factory_path.write_text("<?php echo 'Hello, World!'; ?>")

    result = scanning_utils.scan(factory_path, Xss)

    assert result == []

    factory_path.unlink()
    factory_path.parent.rmdir()


def it_should_execute_path_scan_xss_on_php_file_and_return_result_with_1_vuln():
    """
    Test scan function with a PHP file.
    """

    factory_path = Path("tests/feature/test_php/test.php")
    factory_path.parent.mkdir(parents=True, exist_ok=True)
    factory_path.write_text("<?php echo $_GET['teste'] ?>")

    result = scanning_utils.scan(factory_path, Xss)

    assert result == [("<?php echo $_GET['teste'] ?>", 0, "<?php echo $_GET['teste'] ?>", factory_path)]

    factory_path.unlink()
    factory_path.parent.rmdir()
