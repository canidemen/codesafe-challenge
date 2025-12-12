# 🛡️ Codesafe Security Challenges

A collection of hands-on coding challenges focused on software security, built for the [Codesafe](https://pwn.college) learning platform.

---

## 📚 Available Challenges

### SQL Injection Prevention

| Challenge | Difficulty | Time | Description |
|-----------|------------|------|-------------|
| [Secure the Login System](./sql-injection/secure-login/) | Beginner-Intermediate | 30-60 min | Fix SQL injection vulnerabilities in a user authentication system |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pytest (`pip install pytest`)

### Running a Challenge

```bash
# Navigate to a challenge
cd sql-injection/secure-login

# Read the instructions
cat README.md

# Edit the starter code
# (use your favorite editor)

# Run tests to check your solution
python -m pytest tests.py -v
```

---

## 📁 Repository Structure

```
codesafe-challenge/
├── dojo.yml                          # Dojo configuration
├── README.md                         # This file
└── sql-injection/                    # Module: SQL Injection
    └── secure-login/                 # Challenge: Secure the Login System
        ├── README.md                 # Challenge instructions
        ├── starter.py                # Vulnerable code (edit this!)
        ├── solution.py               # Reference solution
        ├── tests.py                  # Test suite
        └── USER_STORY.md             # User story & learning objectives
```

---

## 🎓 Learning Objectives

By completing these challenges, you will learn to:

- 🔍 **Identify** common security vulnerabilities in code
- 🛠️ **Apply** secure coding practices
- ✅ **Verify** fixes using automated testing
- 💡 **Understand** real-world attack patterns

---

## 📖 About Codesafe

Codesafe is an educational platform designed to teach software security through practical, hands-on coding challenges. Each challenge presents a realistic scenario where learners must identify and fix security vulnerabilities.

---

## 📜 License

This project is for educational purposes as part of UCI coursework.
