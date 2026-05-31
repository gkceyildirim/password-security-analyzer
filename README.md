# Web Vulnerability Scanner

A web security scanner written in Python.

I created this project while learning web application security concepts and practicing Python development. The scanner performs several basic security checks on a target website and generates a simple report of the findings.

## Features

* HTTPS usage detection
* Security header analysis
* Server information disclosure detection
* Directory listing detection
* Console reporting
* Text report generation

## Why I Built This

As a Computer Engineering student interested in cybersecurity, I wanted to better understand how common web security checks work and how security assessment tools are structured.

This project helped me practice:

* Python programming
* HTTP requests and response analysis
* Security header inspection
* Report generation
* Command-line application development

## Technologies

* Python 3
* Requests
* argparse

## Usage

Run a scan:

```bash
python3 main.py https://example.com
```

Save the report:

```bash
python3 main.py https://example.com --save
```

## Legal Notice

Only scan websites that you own or have explicit permission to test.
