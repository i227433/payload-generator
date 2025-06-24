#!/usr/bin/env python3
"""
Test runner script for the Custom Payload Generator
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    """Run all tests"""
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    tests_dir = project_root / "tests"
    
    print("🧪 Running Custom Payload Generator Test Suite")
    print("=" * 50)
    
    # Change to project root
    os.chdir(project_root)
    
    # Install dependencies first
    print("📦 Installing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=False)
    subprocess.run([sys.executable, "-m", "pip", "install", "pytest", "pytest-cov"], check=False)
    
    # Run tests
    print("\n🧪 Running tests...")
    try:
        import pytest
        exit_code = pytest.main([
            str(tests_dir),
            "-v",
            "--tb=short",
            "--color=yes"
        ])
        
        print(f"\n📊 Test Results:")
        if exit_code == 0:
            print("✅ All tests passed!")
        else:
            print(f"❌ Tests failed with exit code: {exit_code}")
        
        return exit_code
    
    except ImportError:
        print("❌ Could not import pytest. Running tests manually...")
        
        # Run basic functionality test
        sys.path.insert(0, str(project_root / "src"))
        
        try:
            print("Testing core functionality...")
            
            from core.payload_generator import PayloadGenerator
            from utils.validators import validate_url, validate_count
            
            # Test basic initialization
            generator = PayloadGenerator()
            print("✅ PayloadGenerator initialized")
            
            # Test validation functions
            assert validate_url("http://example.com") == True
            assert validate_count(5) == True
            print("✅ Validators working")
            
            # Test payload generation
            xss_payloads = generator.generate_xss_payloads(count=2)
            assert isinstance(xss_payloads, list)
            print("✅ XSS payload generation working")
            
            sqli_payloads = generator.generate_sqli_payloads(count=2)
            assert isinstance(sqli_payloads, list)
            print("✅ SQLi payload generation working")
            
            cmdi_payloads = generator.generate_cmdi_payloads(count=2)
            assert isinstance(cmdi_payloads, list)
            print("✅ CMDi payload generation working")
            
            print("\n✅ All basic functionality tests passed!")
            return 0
            
        except Exception as e:
            print(f"❌ Basic functionality test failed: {e}")
            import traceback
            traceback.print_exc()
            return 1

if __name__ == "__main__":
    sys.exit(main())

def run_security_tests():
    """Run security tests"""
    tests = [
        ("bandit -r src/", "Running Bandit security scan"),
        ("safety check", "Checking for vulnerable dependencies")
    ]
    
    success = True
    for command, description in tests:
        if not run_command(command, description):
            success = False
    
    return success

def run_linting():
    """Run code linting"""
    tests = [
        ("flake8 src/ tests/", "Running flake8 linter"),
        ("black --check src/ tests/", "Checking code formatting with black"),
        ("isort --check-only src/ tests/", "Checking import sorting")
    ]
    
    success = True
    for command, description in tests:
        if not run_command(command, description):
            success = False
    
    return success

def run_type_checking():
    """Run type checking"""
    command = "mypy src/ --ignore-missing-imports"
    return run_command(command, "Running type checking with mypy")

def run_functional_tests():
    """Run functional tests with actual payload generation"""
    print("🧪 Running functional tests...")
    
    try:
        # Test basic payload generation
        sys.path.insert(0, 'src')
        from core.payload_generator import PayloadGenerator
        
        generator = PayloadGenerator()
        
        # Test XSS generation
        xss_payload = generator.generate_xss()
        assert xss_payload, "XSS payload generation failed"
        print("✅ XSS payload generation test passed")
        
        # Test SQL injection generation
        sqli_payload = generator.generate_sqli()
        assert sqli_payload, "SQL injection payload generation failed"
        print("✅ SQL injection payload generation test passed")
        
        # Test command injection generation
        cmdi_payload = generator.generate_cmdi()
        assert cmdi_payload, "Command injection payload generation failed"
        print("✅ Command injection payload generation test passed")
        
        print("✅ All functional tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Functional tests failed: {e}")
        return False

def run_cli_tests():
    """Test CLI functionality"""
    print("🧪 Testing CLI functionality...")
    
    cli_tests = [
        ("python src/main.py --help", "Testing help command"),
        ("python src/main.py xss --help", "Testing XSS help"),
        ("python src/main.py sqli --help", "Testing SQLi help"),
        ("python src/main.py cmdi --help", "Testing CMDi help")
    ]
    
    success = True
    for command, description in cli_tests:
        if not run_command(command, description):
            success = False
    
    return success

def generate_test_report(results):
    """Generate a test report"""
    report_file = "test_report.txt"
    
    with open(report_file, 'w') as f:
        f.write("PAYLOAD FORGE TEST REPORT\n")
        f.write("=" * 40 + "\n\n")
        
        total_tests = len(results)
        passed_tests = sum(1 for result in results.values() if result)
        failed_tests = total_tests - passed_tests
        
        f.write(f"Total Tests: {total_tests}\n")
        f.write(f"Passed: {passed_tests}\n")
        f.write(f"Failed: {failed_tests}\n")
        f.write(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%\n\n")
        
        f.write("Test Results:\n")
        f.write("-" * 20 + "\n")
        
        for test_name, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            f.write(f"{test_name}: {status}\n")
    
    print(f"📄 Test report generated: {report_file}")

def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(description="Payload Forge Test Runner")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--unit", action="store_true", help="Run unit tests")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--security", action="store_true", help="Run security tests")
    parser.add_argument("--functional", action="store_true", help="Run functional tests")
    parser.add_argument("--cli", action="store_true", help="Test CLI functionality")
    parser.add_argument("--lint", action="store_true", help="Run linting")
    parser.add_argument("--type-check", action="store_true", help="Run type checking")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--coverage", "-c", action="store_true", help="Generate coverage report")
    parser.add_argument("--report", action="store_true", help="Generate test report")
    
    args = parser.parse_args()
    
    if not any([args.all, args.unit, args.integration, args.performance, 
                args.security, args.functional, args.cli, args.lint, args.type_check]):
        args.all = True
    
    print("🚀 Starting Payload Forge Test Suite")
    print("=" * 40)
    
    results = {}
    
    if args.all or args.unit:
        results["Unit Tests"] = run_unit_tests(args.verbose, args.coverage)
    
    if args.all or args.functional:
        results["Functional Tests"] = run_functional_tests()
    
    if args.all or args.cli:
        results["CLI Tests"] = run_cli_tests()
    
    if args.all or args.lint:
        results["Linting"] = run_linting()
    
    if args.all or args.type_check:
        results["Type Checking"] = run_type_checking()
    
    if args.all or args.security:
        results["Security Tests"] = run_security_tests()
    
    if args.integration:
        results["Integration Tests"] = run_integration_tests()
    
    if args.performance:
        results["Performance Tests"] = run_performance_tests()
    
    # Summary
    print("\n" + "=" * 40)
    print("📊 TEST SUMMARY")
    print("=" * 40)
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    failed_tests = total_tests - passed_tests
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    print(f"\nTotal: {total_tests}, Passed: {passed_tests}, Failed: {failed_tests}")
    
    if failed_tests == 0:
        print("🎉 All tests passed!")
        exit_code = 0
    else:
        print(f"⚠️  {failed_tests} test(s) failed")
        exit_code = 1
    
    if args.report:
        generate_test_report(results)
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
