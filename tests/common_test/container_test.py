from unittest import TestCase
from openwebvulndb.common import Injector


class ContainerTest(TestCase):

    def test_no_injection(self):
        injector = Injector(test="A")
        call = injector.wrap(lambda test: test + test + test)

        self.assertEqual(call(test="B"), "BBB")

    def test_injection(self):
        injector = Injector(test="A")
        call = injector.wrap(lambda test: test + test + test)

        self.assertEqual(call(), "AAA")

    def test_injection_kwargs_only(self):
        injector = Injector(test="A")
        call = injector.wrap(lambda *, test: test + test + test)

        self.assertEqual(call(), "AAA")

    def test_injection_direct_call(self):
        injector = Injector(a='A', b='A')
        value = injector.call(lambda a, b, c: a + b + c, b='B', c='C')
        self.assertEqual(value, "ABC")

    def test_nested_container(self):
        injector = Injector(a='A', b='A')
        sub = Injector(injector, b='B')
        subsub = sub.sub(c='C')

        self.assertEqual(subsub.call(lambda a, b, c: a + b + c), 'ABC')
        self.assertEqual(subsub.create(lambda a, b, c: a + b + c), 'ABC')

    def test_direct_access(self):
        injector = Injector(test="A")

        self.assertEqual("A", injector.test)

    def test_direct_access_no_data(self):
        injector = Injector()

        with self.assertRaises(AttributeError):
            injector.test

    def test_jit_instance(self):
        item = Exception()

        injector = Injector(test=lambda: item)

        self.assertIs(item, injector.test)

    def test_jit_instance_always_the_same_result(self):
        injector = Injector(test=self.__class__)

        self.assertIs(injector.test, injector.test)

    def test_dependency_chain(self):
        injector = Injector(a="A", b="B", test=lambda a, b: a + b)

        self.assertEqual(injector.test, "AB")

    def test_dependency_chain_longer(self):
        injector = Injector(a="A", b=lambda a: a, test=lambda a, b: a + b)

        self.assertEqual(injector.test, "AA")

    def test_create_instances(self):
        injector = Injector(test=Injector)

        self.assertIsInstance(injector.test, Injector)

    def test_dependency_chain_circular(self):
        injector = Injector(a="A", b=lambda test: test, test=lambda a, b: a + b)

        with self.assertRaises(RecursionError):
            injector.test
