# PostHog Dashboard Cloner

## Overview

The PostHog Dashboard Cloner is a Go application designed to clone dashboards from one PostHog project to another. This tool is particularly useful for migrating dashboards between different environments or accounts. It moves tiles from a source dashboard to a destination dashboard, ensuring that the original dashboard is duplicated before the operation to prevent data loss.

## Features

- **Interactive and Non-Interactive Modes**: The application can run in interactive mode, prompting the user for input, or in non-interactive mode using environment variables.
- **SSL Configuration**: Supports custom SSL certificates and the option to disable SSL verification.
- **Dashboard Management**: Retrieves, creates, and updates dashboards using the PostHog API.

## Prerequisites

- Go (version 1.23.5 or later)
- A PostHog account with API access
- Environment variables set for non-interactive mode (optional)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/manuelOsterloh/dM-postHog-cloner.git
   ```
2. Navigate to the project directory:
   ```bash
   cd dM-postHog-cloner
   ```
3. Install dependencies:
   ```bash
   go mod tidy
   ```

## Usage

### Interactive Mode

Run the application and follow the prompts:

```bash
go run main.go
```

### Non-Interactive Mode

Set the following environment variables before running the application:

- `PH_API_KEY`: Your PostHog Personal API Key
- `SOURCE_PROJECT_ID`: The ID of the source project
- `SOURCE_DASHBOARD_ID`: The ID of the source dashboard
- `DESTINATION_PROJECT_ID`: The ID of the destination project
- `SSL_CERT_PATH`: Path to the SSL certificate (optional)
- `DISABLE_SSL`: Set to "true" to disable SSL verification (optional)

Then execute:

```bash
go run main.go -noninteractive
```
