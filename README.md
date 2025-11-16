# Telegram AES-256 File Encryptor Bot

This is a Telegram bot that allows users to encrypt and decrypt files using AES-256 encryption. The bot supports various file types including documents, photos, audio, and video files. It can encrypt files and send them back, store encrypted files on the server, and retrieve and decrypt them later.

## Features

- **AES-256 Encryption**: Secure file encryption using AES-256 in CBC mode with random IVs.
- **File Types Supported**: Documents, photos, audio, and video files.
- **Commands**:
  - `/encrypt`: Encrypt a file and send it back to the user.
  - `/decrypt`: Decrypt an uploaded encrypted file.
  - `/upload`: Encrypt a file and store it on the server.
  - `/download`: Download and decrypt a stored file.
  - `/list`: List all stored encrypted files.
  - `/info`: Get information about the bot.
  - `/help`: Show available commands.
- **Security**: Passwords are required for encryption/decryption, and password messages are deleted after use for privacy.
- **Temporary Storage**: Files are temporarily stored during processing and cleaned up afterward.

## Prerequisites

- Python 3.7+
- A Telegram Bot API Token (obtain from [@BotFather](https://t.me/botfather) on Telegram)
- Required Python libraries:
  - `pyTelegramBotAPI` (for Telegram bot functionality)
  - `pycryptodome` (for AES encryption)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/pabloibiza/telegram_bot_encryptor.git
   cd telegram_bot_encryptor
   ```

2. Install the required libraries:
   ```bash
   pip install pyTelegramBotAPI pycryptodome
   ```

3. Set up your bot token:
   - Open `aes256_bot.py` and replace `'YOUR_TELEGRAM_BOT_API_TOKEN'` with your actual bot token from BotFather.

## Usage

1. Run the bot:
   ```bash
   python aes256_bot.py
   ```

2. Interact with the bot on Telegram:
   - Start a chat with your bot.
   - Use commands like `/encrypt` followed by providing a password and the file to encrypt.

### Commands Details

- **/start or /help**: Display help text with available commands.
- **/info**: Show information about the bot.
- **/encrypt**: 
  - Send the command.
  - Provide a password when prompted.
  - Send the file to encrypt.
  - The bot will encrypt the file and send it back with the IV (Initialization Vector).
- **/upload**:
  - Similar to `/encrypt`, but the encrypted file is stored on the server instead of being sent back.
- **/decrypt**:
  - Send the command.
  - Provide a password when prompted.
  - Send the encrypted file (which must have the IV in the filename).
  - The bot will decrypt and send the original file.
- **/download**:
  - Send the command.
  - Provide the filename (without IV or extension).
  - Provide the password.
  - The bot will decrypt the stored file and send it.
- **/list**: List all stored encrypted files.

### File Naming Convention

- Encrypted files are saved with the format: `original_name_ivHEX.enc`
- When decrypting, ensure the IV is included in the filename.

## Security Notes

- Remember your passwords! There is no way to recover files without the correct password.
- Password messages are automatically deleted after operations for privacy.
- Each file uses a unique IV for added security.
- The bot deletes original files after encryption and temporary files after processing.

## Contributing

Feel free to fork the repository and submit pull requests for improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details. (Note: Add a LICENSE file if not present.)

## Disclaimer

This bot is for educational and personal use. Ensure compliance with laws regarding data encryption and privacy in your jurisdiction. The authors are not responsible for misuse or data loss.