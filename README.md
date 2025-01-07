# Code Vulnerability Scanner

This project is a simple code vulnerability scanner that scans JavaScript files for potential vulnerabilities and generates an HTML report.

## Report Sample in HTML format from a webpage

![Report Sample](/report.png)

## Features

- Scans JavaScript files for potential vulnerabilities.
- Generates an HTML report with the scan results.
- Detects usage of environment variables in the code.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Taiwrash/vunenv.git
   
    cd vunenv
    ```

2. Install dependencies:
    ```sh
    go mod tidy
    ```

## Usage

1. Run the scanner:
    ```sh
    go run main.go <full/path/to/of/code/to/test/>
    ```

2. The scanner will generate an HTML report named [report.html](/report.html) in the project directory.

