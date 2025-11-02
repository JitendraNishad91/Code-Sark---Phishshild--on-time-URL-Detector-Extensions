
<a name="readme-top"></a>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-">
    <img src="phishshield128.png" alt="Logo" width="120" height="120">
  </a>

<h3 align="center">PhishShield</h3>
  
  <p align="center">
    A Chrome extension that alerts users when they navigate to potentially malicious or phishing websites. Built for RobHacks conducted by Nosu.
    <br />
    <a href="https://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href = "https://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-">View Demo</a>
    ·
    <a href="https://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-/issues">Report Bug</a>
    ·
    <a href="https://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-/issues">Request Feature</a>
  </p>
</div>




<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Issues</a></li>
    <li><a href="#contact">Contact</a></li.
  </ol>
</details><br>



<!-- ABOUT THE PROJECT -->
## About The Project

PhishShield is a lightweight, AI-powered browser extension designed to detect and prevent phishing attacks in real time. By analyzing URLs using machine learning models, it helps users identify potentially malicious links before they interact with them.

PhishShield leverages a trained classification model to assess URL attributes and predict the likelihood of a phishing attempt. The extension seamlessly integrates with the browser to provide instant warnings, enhancing cybersecurity for everyday users.

### Built With

[![tools](https://skillicons.dev/icons?i=py,js,sklearn,html,css,github,gcp)](https://skillicons.dev)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running, follow these steps:

### Cloning the repository

```bash
> git clone https://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-.git
```

## Installation Guide
You can either clone the repo using Git or download the ZIP manually.

### Clone using Git
git clonehttps://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-
cd phishshield

### Create virtual environment
python -m venv venv

### Activate it
### For Windows:
venv\Scripts\activate
### For Mac/Linux:
source venv/bin/activate

### Install dependencies
pip install -r requirnment.txt

### run the python file
  python app.py

### Setting up the extension

1. Open Google Chrome and navigate to ```chrome://extensions/```

2. Enable Developer Mode (toggle in the top right corner)

3. Click Load Unpacked and select the PhishShield project directory

4. The extension should now be available in your browser

### Running the machine learning model

PhishShield uses a pre-trained model for phishing detection. The model is lightweight and optimized for browser-based execution.

Ensure the saved model file (phishshield_model.onnx) is present in the extension directory. The extension will automatically load and use the model when analyzing URLs.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

# 🧠 Usage / Examples

PhishShield works automatically in the background once installed.  
Follow the examples below to understand how it behaves with different URLs 👇

---

## 🧩 Example 1 — Safe Website

**https://www.youtube.com/**  


**Process:**  
PhishShield sends this URL to the backend `/predict` API.  
Backend response:
```json
{
  "risk_percent": 29,
  "label_pred": "safe"
}
```
 <img src="Screenshot 2025-11-01 223716.png" alt="Logo" width="400" height="400" align-item = "centre" display = "flex">
  </a>


## 🧩 Example 2 — Suspicious or Phishing Website

**https://bdg2612.com/#/?invitationCode=3167117838046**  


**Process:**  
PhishShield sends this URL to the backend `/predict` API.  
Backend response:
```json
{
  "risk_percent": 89,
  "label_pred": "phishing "
}
```

**Result** 
Block the website 

<img src="Screenshot 2025-11-01 223757.png" alt="Logo" width="400" height="400" align-item = "centre" display = "flex" >
  </a>
  <img src="Screenshot 2025-11-01 223737.png" alt="Logo" width="400" height="400" align-item = "centre" display = "flex">
    </a>
  




<!-- ISSUES -->
## Issues

See the [open issues](https://github.com/JitendraNishad91/Code-Smesher---Phishshield-url-detection-/issues) for a full list of known issues, priorities and assignees.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CREATED BY -->
## Created by

* Code Sark - [@JitendraNishad91](https://github.com/JitendraNishad91) - sc21vs@leeds.ac.uk


### Project Links:

* [Project Repository](https://github.com/JitendraNishad91?tab=repositories)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
