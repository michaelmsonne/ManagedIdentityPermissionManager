# Azure Managed Identity Permissions Tool

## Introduction
Welcome to the **Azure Managed Identity Permissions Tool**, a new PowerShell tool that simplifies and streamlines the management of Managed Identity permissions in **Azure (Entra ID)**.

Whether you're a system administrator or a developer, this tool offers a powerful yet user-friendly way to manage permissions, ensuring security, efficiency, and transparency. With this release, I've focused on creating an all-in-one solution for handling Managed Identity permissions, making it easier to avoid risks and errors.  

Your feedback and support are always welcome! 🤩🤘

## Why This Tool is Needed
Many existing solutions for managing Managed Identity permissions lack the ease of use and cohesion that this tool provides. This PowerShell tool solves those issues by offering:

- **Simplicity**: Consolidates everything in one place—no need to search for scripts.
- **Security**: Confirmation prompts for high-risk tasks, with full logging for audit transparency.
- **Efficiency**: Handles permissions for both single identities and large-scale operations with ease.

## How This Tool Will Help You
- **Build Confidence**: Logging and confirmations provide peace of mind.
- **Save Time**: No more script-hunting; everything is centralized.
- **Reduce Errors**: User-friendly steps and prompts help avoid mistakes.
- **Increase Efficiency**: Easily manage permissions for multiple identities or APIs.

## Key Features
The initial release of the tool comes with several key features that make it indispensable:

- **List all Managed Identities**: Retrieve a complete list of Managed Identities in your Azure environment.
- **View Assigned Permissions**: Quickly view current permissions assigned to any Managed Identity.
- **Support for Multiple Access Scopes**: Manage permissions for various APIs like Microsoft Graph.
- **Add Permissions Without Overwriting**: Add new permissions without losing existing ones.
- **Set Permissions by Resetting Assignments**: Reset and apply new permissions from scratch.
- **Remove Individual Permissions**: Remove specific permissions from an identity.
- **Remove All Permissions**: Strip all permissions when retiring or decommissioning identities.
- **List Access Scopes with Filtering**: Filter available access scopes for easier management.
- **Confirmation for High-Risk Tasks**: Prompts for tasks like removing all permissions.
- **Full Logging for Transparency**: Logs all actions for audit purposes.

## Screenshot

To be continued...

![Sample Screenshot](./docs/Managed%20Identity%20Permission%20Manager.png)

## Development History
From the early Proof of Concept (PoC) to the official release, this tool has evolved with new features and improvements based on feedback. Check out the development updates on LinkedIn for a behind-the-scenes look:

- [LinkedIn Post 1](https://www.linkedin.com/feed/update/urn:li:activity:7253164999236329472/)
- [LinkedIn Post 2](https://www.linkedin.com/feed/update/urn:li:activity:7254182659118030848/)

## Download
Ready to take control of your Managed Identity permissions? Download the tool now and get started:

> **Download the tool here (coming soon)**

- [GitHub Releases](https://github.com/michaelmsonne/ManagedIdentityPermissionManager/releases)

---

## Getting Started

### Prerequisites
- **PowerShellMicrosoft Graph PowerShell** installed on your machine (Microsoft.Graph.Authentication, Microsoft.Graph.Applications)
- **Azure/Entra ID Directory** permissions to manage Managed Identities and access scopes.

### Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/YourUsername/AzureManagedIdentityTool.git
