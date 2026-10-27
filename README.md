# AI-ScamSheild

# PhishingRisk AI

An AI-assisted web application for analyzing URLs and identifying potential phishing risks.

## 🚀 Features

- URL phishing risk analysis
- Risk score from 0 to 100
- Risk classification: Low, Medium, or High
- Security indicators explaining potential risks
- Browser-based interface using Flask
- Local execution on your computer
- Automated testing using pytest
- Analysis history, if configured

## 🛠️ Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- SQLite, if configured
- scikit-learn, if used by the implementation
- pytest

## 📋 Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer, compatible with the installed dependencies
- Visual Studio Code
- A modern web browser

## 📂 Project Structure

```text
PhishingRisk-AI/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
├── data/
├── models/
├── scripts/
├── src/
├── static/
├── templates/
├── tests/
└── .venv/
```

## ⚙️ Installation

### 1. Open the Project

```powershell
cd D:\RAJA\PhishingRisk-AI
```

### 2. Create a Virtual Environment

```powershell
python -m venv .venv
```

### 3. Activate the Virtual Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

## ▶️ Run the Application

Start the Flask server:

```powershell
python app.py
```

Open your browser and visit:

http://127.0.0.1:5000

Keep the terminal open while using the application.

To stop the server, press `Ctrl + C` in the terminal.

## 🧪 Run Tests

Run the automated tests using:

```powershell
python -m pytest
```

## 🔍 How It Works

1. The user enters a URL into the application.
2. The application validates the URL.
3. The analysis logic examines supported URL characteristics.
4. A risk score is calculated using the implemented rules or model.
5. The result is classified as Low, Medium, or High risk.
6. The application displays the score and relevant security indicators.

## 🔐 Security and Privacy

- Avoid automatically visiting submitted URLs during analysis.
- Validate user input before processing it.
- Escape user-provided content before displaying it.
- Use parameterized SQL queries for database operations.
- Never enter passwords or confidential information into suspicious websites.
- Do not assume a low risk score guarantees that a URL is safe.

## ⚠️ Limitations

- Some phishing URLs may not be detected.
- Legitimate URLs may occasionally be flagged.
- URL analysis alone cannot identify every phishing technique.
- Detection accuracy depends on the implemented logic, model, and available data.
- This project is intended for learning and demonstration purposes.

## 🛣️ Future Enhancements

- Integrate a trained machine learning model.
- Improve phishing detection accuracy.
- Add detailed risk indicators and visualizations.
- Enhance analysis history and reporting.
- Expand automated test coverage.
- Improve the user interface and mobile responsiveness.

## 👨‍💻 Developer

Developed as a Python-based cybersecurity learning project to explore phishing detection, web development, and AI-assisted security analysis.

## 📄 License

No license has been specified yet.
