# 🛡️ sentinel-detection-engine - Identify security threats with clear automation

[![Download Latest Release](https://img.shields.io/badge/Download-Release-blue)](https://github.com/thomdefinable658/sentinel-detection-engine)

## Overview 🔎

The sentinel-detection-engine provides a set of tools to monitor your environment. It helps you track suspicious activity across your network. This engine contains analytic rules, hunting queries, and playbooks. These tools work together to flag potential security risks. You gain clear visibility into your cloud and endpoint traffic. This improves your ability to respond to incidents.

## Features ⚙️

This engine includes tools to support your security work:

* Analytic Rules: These monitor logs to flag dangerous patterns.
* Hunting Queries: You use these to search for hidden threats.
* SOAR Playbooks: These automate your incident response steps.
* ATT&CK Navigator Maps: These track your security coverage.
* Documentation: You get guides on how to handle alerts.

## Requirements 🖥️

Your computer needs the following setup to run these tools:

* Operating System: Windows 10 or 11.
* Connection: Active internet access.
* Permissions: Admin rights to manage your security portal.
* Software: A browser to access your Microsoft Sentinel portal.

## How to Obtain the Software 📥

Follow these steps to access the engine:

1. Visit the project page to download the files: https://github.com/thomdefinable658/sentinel-detection-engine
2. Click the green "Code" button on the webpage.
3. Select "Download ZIP" from the menu.
4. Save the file to your computer.
5. Right-click the folder and choose "Extract All".

## Setting Up the Tools 🛠️

Once you extract the files, perform these steps to link the engine to your environment:

1. Open your Microsoft Sentinel instance in your web browser.
2. Select the "Configuration" menu on the left side.
3. Choose "Repositories" to connect this folder to your cloud workspace.
4. Use the provided KQL files to create new analytic rules.
5. Copy the query text from the files into the rule editor.
6. Save your changes to activate the detection.

## Using the Analytic Rules 📊

The analytic rules run in the background. They check your logs every few hours. When the system detects a threat, it generates an alert. You view these alerts in your Security Dashboard. Each alert includes details about the source of the risk. We recommend you review these once each morning to maintain safety.

## Managing Hunting Queries 🎯

Hunting queries help you find security gaps. You find these files in the "Hunting" folder of your download. To run a query, copy the text into the "Logs" section of the Microsoft Sentinel portal. Press the "Run" button to see the results. Use these queries when you suspect an unauthorized person is on your network.

## Configuring Playbooks 🤖

Playbooks reduce your manual work. They move data to the right people when an event occurs. Open the "Playbooks" folder to find the logic templates. You load these into the Logic Apps section of your dashboard. They guide you through the process of containing a threat.

## Maintaining Your Coverage 📈

Security evolves every day. You should check this repository for updates each month. We update the rules to reflect new threat patterns. If you notice a gap in your defense, look at the ATT&CK Navigator map in the documentation. This shows which areas need more attention.

## Understanding the Workflow 📝

Effective security requires a process. This engine uses a set workflow for all alerts.

1. Detection: The rule triggers an alert based on your criteria.
2. Triage: You confirm if the threat is internal or external.
3. Response: You run a playbook to isolate the affected device.
4. Investigation: You check the logs to see how the threat entered.
5. Resolution: You close the incident once the threat finishes.

## Frequently Asked Questions 💡

Do I need programming skills?
No. All tasks rely on copying and pasting text into your dashboard menus.

Will this slow down my computer?
No. The engine runs in your Microsoft cloud portal, not on your local machine.

Can I customize the alerts?
Yes. You can edit the parameters within each query file.

How do I report an issue?
Use the "Issues" tab on the repository webpage to send feedback to the team.

What if a rule creates too many alerts?
Edit the rule and include a condition to ignore common, safe events.

Are there more resources available?
Check the "docs" folder in your download for detailed guides on every feature.