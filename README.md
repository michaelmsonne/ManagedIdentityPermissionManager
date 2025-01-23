# Azure / Entra ID Managed Identity Permission Manager

<p align="center">
  <a href="https://github.com/michaelmsonne/ManagedIdentityPermissionManager"><img src="https://img.shields.io/github/languages/top/michaelmsonne/ManagedIdentityPermissionManager.svg"></a>
  <a href="https://github.com/michaelmsonne/ManagedIdentityPermissionManager"><img src="https://img.shields.io/github/languages/code-size/michaelmsonne/ManagedIdentityPermissionManager.svg"></a>
  <a href="https://github.com/michaelmsonne/ManagedIdentityPermissionManager"><img src="https://img.shields.io/github/downloads/michaelmsonne/ManagedIdentityPermissionManager/total.svg"></a><br>
  <a href="https://www.buymeacoffee.com/sonnes" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 30px !important;width: 117px !important;"></a>
</p>

<div align="center">
  <a href="https://github.com/michaelmsonne/ManagedIdentityPermissionManager/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+">Report a Bug</a>
  ·
  <a href="https://github.com/michaelmsonne/ManagedIdentityPermissionManager/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+">Request a Feature</a>
  .
  <a href="https://github.com/michaelmsonne/ManagedIdentityPermissionManager/discussions">Ask a Question</a>
</div>

<div align="center">
<br />

</div>

## Table of Contents
- [Introduction](#introduction)
- [Contents](#contents)
- [Features](#features)
- [Download](#download)
- [Getting Started](#getting-started)
  - [Known bugs](#known-bugs)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

# Introduction
Welcome to the **Azure Managed Identity Permissions Tool**, a new PowerShell tool that simplifies and streamlines the management of Managed Identity permissions in **Azure (Entra ID)**.

Whether you're a system administrator or a developer, this tool offers a powerful yet user-friendly way to manage permissions, ensuring security, efficiency, and transparency. With this release, I've focused on creating an all-in-one solution for handling Managed Identity permissions, making it easier to avoid risks and errors.  

Your feedback and support are always welcome! 🤩🤘

## Why this tool is needed in the community
Many existing solutions for managing Managed Identity permissions lack the ease of use and cohesion that this tool provides. This PowerShell tool solves those issues by offering:

- **Simplicity**: Consolidates everything in one place—no need to search for scripts.
- **Security**: Confirmation prompts for high-risk tasks, with full logging for audit transparency.
- **Efficiency**: Handles permissions for both single identities and large-scale operations with ease.

## How this tool will help you
- **Build confidence**: Logging and confirmations provide peace of mind.
- **Save time**: No more script-hunting; everything is centralized.
- **Reduce errors**: User-friendly steps and prompts help avoid mistakes.
- **Increase efficiency**: Easily manage permissions for multiple identities or APIs.

## Contents

Outline the file contents of the repository. It helps users navigate the codebase, build configuration and any related assets.

| File/folder                  | Description                                 |
|------------------------------|---------------------------------------------|
| `src`                        | Code for tool                               |
| `docs`                       | Documents/pictures.                         |
| `.gitignore`                 | Define what to ignore at commit time.       |
| `CHANGELOG.md`               | List of changes to the tool.                |
| `CONTRIBUTING.md`            | Guidelines for contributing.                |
| `README.md`                  | This README file.                           |
| `SECURITY.md`                | Security file.                              |
| `LICENSE`                    | The license for the tool.                   |

## Features
The initial release of the tool comes with several key features that make it indispensable:

- **List all Managed Identities**: Retrieve a complete list of Managed Identities in your Azure environment.
- **View assigned permissions**: Quickly view current permissions assigned to any Managed Identity.
- **Support for multiple access scopes**: Manage permissions for various APIs like Microsoft Graph.
- **Add permissions without overwriting**: Add new permissions without losing existing ones.
- **Set permissions by resetting assignments**: Reset and apply new permissions from scratch.
- **Remove individual permissions**: Remove specific permissions from an identity.
- **Remove all permissions**: Strip all permissions when retiring or decommissioning identities.
- **List access Scopes with filtering**: Filter available access scopes for easier management.
- **Confirmation for High-Risk tasks**: Prompts for tasks like removing all permissions.
- **Full logging for transparency**: Logs all actions for audit purposes.

## Screenshot

To be continued...

![Sample Screenshot](./docs/Managed%20Identity%20Permission%20Manager.png)

## Download
Ready to take control of your Managed Identity permissions? Download the tool now and get started:

[Download the latest version](../../releases/latest)

[Version History](CHANGELOG.md)

---

## Getting started

### Known bugs
- None

### Prerequisites
- **PowerShellMicrosoft Graph PowerShell** installed on your machine (Microsoft.Graph.Authentication, Microsoft.Graph.Applications)
- **Azure/Entra ID Directory** permissions to manage Managed Identities and access scopes.

####
- For changes, **PowerShell Studio** is it for now

## Development history
From the early Proof of Concept (PoC) to the official release, this tool has evolved with new features and improvements based on feedback. Check out the development updates on LinkedIn for a behind-the-scenes look:

- [LinkedIn Post 1](https://www.linkedin.com/feed/update/urn:li:activity:7253164999236329472/)
- [LinkedIn Post 2](https://www.linkedin.com/feed/update/urn:li:activity:7254182659118030848/)

# Contributing
If you want to contribute to this project, please open an issue or submit a pull request. I welcome contributions :)

See [CONTRIBUTING](CONTRIBUTING) for more information.

First off, thanks for taking the time to contribute! Contributions are what makes the open-source community such an amazing place to learn, inspire, and create. Any contributions you make will benefit everybody else and are **greatly appreciated**.
Feel free to send pull requests or fill out issues when you encounter them. I'm also completely open to adding direct maintainers/contributors and working together! :)

Please try to create bug reports that are:

- _Reproducible._ Include steps to reproduce the problem.
- _Specific._ Include as much detail as possible: which version, what environment, etc.
- _Unique._ Do not duplicate existing opened issues.
- _Scoped to a Single Bug._ One bug per report.

# Support

Commercial support

This project is open-source and I invite everybody who can and will to contribute, but I cannot provide any support because I only created this as a "hobby project" ofc. with tbe best in mind. For commercial support, please contact me on LinkedIn so we can discuss the possibilities. It’s my choice to work on this project in my spare time, so if you have commercial gain from this project you should considering sponsoring me.

<a href="https://www.buymeacoffee.com/sonnes" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 30px !important;width: 117px !important;"></a>

Thanks.

Reach out to the maintainer at one of the following places:

- [GitHub discussions](https://github.com/michaelmsonne/ManagedIdentityPermissionManager/discussions)
- The email which is located [in GitHub profile](https://github.com/michaelmsonne)

# License
This project is licensed under the **MIT License** - see the LICENSE file for details.

See [LICENSE](LICENSE) for more information.
