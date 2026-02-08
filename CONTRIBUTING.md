# Contributing to FridaForge

⚔️ Thank you for your interest in contributing to FridaForge!

## 🚀 How to Contribute

### Reporting Bugs

1. Check if the bug is already reported in [Issues](https://github.com/YOUR_USERNAME/fridaforge/issues)
2. If not, create a new issue with:
   - Clear title
   - Detailed description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Log files if applicable

### Suggesting Features

1. Open an issue with the `feature-request` label
2. Describe the feature and use case
3. Explain why it would be valuable
4. Provide examples if possible

### Code Contributions

#### Setup Development Environment

```bash
git clone https://github.com/YOUR_USERNAME/fridaforge.git
cd fridaforge
./setup.sh
./run.sh --dev
```

#### Before Submitting

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/your-feature-name`
3. **Make changes** with clear commits
4. **Test thoroughly** with multiple APKs
5. **Update documentation** if needed
6. **Submit pull request** with description

#### Code Style

- Python: Follow PEP 8
- Comments: Clear and concise
- Functions: Descriptive names
- Error handling: Comprehensive

#### Testing

```bash
# Test with various APKs
./run.sh --dev

# Check logs
tail -f logs/app.log

# Test API endpoints
curl http://localhost:8000/api/
```

### Adding New Detection Patterns

To add a new security protection detection:

1. Update `IntelligentCodeAnalyzer` class
2. Add keywords to `security_keywords` dict
3. Add analysis logic to `_analyze_method_protection`
4. Test with real APKs containing that protection
5. Document in README.md

### Improving AI Script Generation

To enhance Frida script quality:

1. Update prompts in `AIFridaScriptGenerator`
2. Add more context to AI
3. Include examples of good bypasses
4. Test generated scripts with Frida

## 🎯 Priority Areas

We especially welcome contributions in:

- 🤖 AI agent system implementation
- 🍎 iOS IPA analysis improvements
- 📊 Advanced reporting features
- 🔧 Performance optimizations
- 📝 Documentation improvements
- 🧪 Test coverage

## 💬 Communication

- **Issues**: For bugs and features
- **Discussions**: For questions and ideas
- **Pull Requests**: For code contributions

## 📜 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow ethical security practices

## ⚖️ Legal

By contributing, you agree that:

- Your contributions will be licensed under MIT
- You have rights to submit the contribution
- The tool is for authorized testing only

---

**Thank you for making FridaForge better!** ⚔️
