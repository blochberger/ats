from setuptools import setup, find_packages


def readme() -> str:
	with open('README.md', 'r') as f:
		return f.read()


setup(
	name='ats',
	version='0.0.0',
	author='Maximilian Blochberger',
	packages=find_packages(),
	platforms=['darwin'],
	python_requires='>=3.9',
	long_description=readme(),
	long_description_content_type='text/markdown',
	install_requires=[
		'click',
		'lief',
		'matplotlib',
		'natsort',
		'pyopenssl',
		'tqdm',
	],
	extras_require=dict(
		test=[
			'ddt',
		],
	),
	entry_points=dict(
		console_scripts=[
			'ats=main:cli',
		],
	),
)
