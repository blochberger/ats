from setuptools import setup, find_packages


def readme() -> str:
	with open('README.md') as f:
		return f.read()


setup(
	name='ats',
	version='0.0.1',
	author='Maximilian Blochberger',
	url='https://github.com/blochberger/ats',
	license='ISC',
	packages=find_packages(),
	platforms=['darwin'],
	python_requires='>=3.9',
	long_description=readme(),
	long_description_content_type='text/markdown',
	classifiers=[
		'Environment :: Console',
		'Environment :: MacOS X',
		'Intended Audience :: Developers',
		'License :: OSI Approved :: ISC License (ISCL)',
		'Operating System :: MacOS',
		'Operating System :: iOS',
		'Topic :: Internet',
		'Topic :: Security',
		'Topic :: Software Development :: Build Tools',
		'Topic :: Software Development :: Quality Assurance',
		'Topic :: System :: Networking',
		'Topic :: Utilities',
		'Typing :: Typed',
	],
	install_requires=[
		'click',
		'lief',
		'matplotlib',
		'natsort',
		'pyopenssl',
		'requests',
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
