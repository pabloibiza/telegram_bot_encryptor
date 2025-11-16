import asyncio
import hashlib
from telebot.async_telebot import AsyncTeleBot # Requires pyTelegramBotAPI library
import os
from Crypto.Cipher import AES # Requires pycryptodome library


# Bot configuration
API_TOKEN = 'YOUR_TELEGRAM_BOT_API_TOKEN'
TEMPORARY_DIR_NAME = 'temp'
ENCRYPTED_DIR_NAME = 'files'

# Bot texts
HELP_TEXT = """
🤖 *__Available commands:__*
 /help \- Show this help
 /info \- Information about the bot
 /encrypt \- Encrypt a file
 /decrypt \- Decrypt a file
 /upload \- Encrypt and store a file
 /download \- Download and decrypt a stored file
 /list \- List all stored encrypted files
"""
INFO_TEXT = """
🤖 *__AES\-256 File Encryption Bot__*
 \- Encrypts and decrypts files using AES\-256\.
 \- Files can be sent as documents, photos, audio, or video\.
 \- Encrypted files are stored with a unique IV for each file\.
 \- Ensure to remember your password, as it is required for decryption\.
 """

# User states
waiting_for_file = {}
waiting_for_operation = {}
waiting_for_filename = {}
waiting_for_password = {}
waiting_for_password_download = {}
user_passwords = {}
pending_download = {}
password_message_ids = {}

bot = AsyncTeleBot(API_TOKEN)


# Handle /start and /help commands.
@bot.message_handler(commands=['start', 'help'])
async def send_welcome(message):
	await bot.send_message(message.chat.id, HELP_TEXT, parse_mode='MarkdownV2')


# Handle /info command.
@bot.message_handler(commands=['info'])
async def send_welcome(message):
	await bot.send_message(message.chat.id, INFO_TEXT, parse_mode='MarkdownV2')


# Handle /list command. Lists all encrypted files in the encrypted directory.
@bot.message_handler(commands=['list'])
async def list_files(message):
	encrypted_dir = os.path.join(os.path.dirname(__file__), ENCRYPTED_DIR_NAME)
	files = os.listdir(encrypted_dir)
	display_names = [f.split('_iv')[0] for f in files] # Display names without the IV part.
	if display_names:
		await bot.send_message(message.chat.id, "Ciphered files:\n" + "\n".join(display_names))
	else:
		await bot.send_message(message.chat.id, "No ciphered files found.")


# Handle /download command. Sets the bot to wait for a file name to download.
@bot.message_handler(commands=['download'])
async def download_files(message):
	user_id = message.from_user.id
	await bot.send_message(message.chat.id, "Send file name to download (with extension):")
	waiting_for_filename[user_id] = True


# Handle text messages when waiting for a filename.
@bot.message_handler(func=lambda message: waiting_for_filename.get(message.from_user.id, False))
async def handle_text(message):
	user_id = message.from_user.id
	file_name = message.text.strip()
	
	# Search for the file in the encrypted directory
	encrypted_dir = os.path.join(os.path.dirname(__file__), ENCRYPTED_DIR_NAME)
	
	if os.path.exists(encrypted_dir):
		for file in os.listdir(encrypted_dir):
			if file.startswith(file_name + "_iv") and file.endswith(".enc"):
				# File found, proceed to ask for password
				pending_download[user_id] = file_name
				waiting_for_filename[user_id] = False
				waiting_for_password_download[user_id] = True
				await bot.send_message(message.chat.id, "Send the password for decryption")
				return
	
	# File not found
	await bot.send_message(message.chat.id, f"File '{file_name}' not found.")
	waiting_for_filename[user_id] = False


# Handle /encrypt command. Encrypts and sends the file to the user.
@bot.message_handler(commands=['encrypt'])
async def encrypt_file(message):
	user_id = message.from_user.id
	waiting_for_password[user_id] = "encrypt_send"
	await bot.send_message(message.chat.id, "Send the password for encryption")


# Handle /upload command. Encrypts and stores the file in encrypted directory.
@bot.message_handler(commands=['upload'])
async def upload_file(message):
	user_id = message.from_user.id
	waiting_for_password[user_id] = "encrypt_store"
	await bot.send_message(message.chat.id, "Send the password for encryption")


# Handle /decrypt command. Sets the bot to wait for a file to decrypt.
@bot.message_handler(commands=['decrypt'])
async def decrypt_file(message):
	user_id = message.from_user.id
	waiting_for_password[user_id] = "decrypt"
	await bot.send_message(message.chat.id, "Send the password for decryption")
	

# Handle text messages when waiting for a password.
@bot.message_handler(func=lambda message: waiting_for_password.get(message.from_user.id, False))
async def handle_password(message):
	user_id = message.from_user.id
	operation = waiting_for_password[user_id]
	user_passwords[user_id] = message.text.strip()
	password_message_ids[user_id] = message.message_id  # Save message ID to delete later
	waiting_for_password[user_id] = False
	waiting_for_file[user_id] = True
	waiting_for_operation[user_id] = operation
	
	if operation == "encrypt_send":
		await bot.send_message(message.chat.id, "Send the file you want to encrypt")
	elif operation == "encrypt_store":
		await bot.send_message(message.chat.id, "Send the file you want to upload (encrypt and store)")
	elif operation == "decrypt":
		await bot.send_message(message.chat.id, "Send the file you want to decrypt")


# Handle text messages when waiting for a password.
@bot.message_handler(func=lambda message: waiting_for_password_download.get(message.from_user.id, False))
async def handle_download_password(message):
	user_id = message.from_user.id
	password = message.text.strip()
	file_name = pending_download[user_id]
	password_message_id = message.message_id
	
	# Search for the file in the encrypted directory and send it if found.
	encrypted_dir = os.path.join(os.path.dirname(__file__), ENCRYPTED_DIR_NAME)
	temp_dir = os.path.join(os.path.dirname(__file__), TEMPORARY_DIR_NAME)
	os.makedirs(temp_dir, exist_ok=True)
	
	if os.path.exists(encrypted_dir):
		for file in os.listdir(encrypted_dir):
			if file.startswith(file_name + "_iv") and file.endswith(".enc"):
				encrypted_file_path = os.path.join(encrypted_dir, file)
				
				# Extract the IV from the filename (part between _iv and .enc)
				iv_hex = file.split("_iv")[-1].split(".enc")[0]
				iv = bytes.fromhex(iv_hex)
				
				# Decrypt the file using the extracted IV
				decrypted_file_path = os.path.join(temp_dir, file_name)
				try:
					# Try to decrypt first
					decrypt_file(password, iv, encrypted_file_path, decrypted_file_path)
					# Only send messages if decryption succeeded
					await bot.send_message(message.chat.id, f"Sending decrypted file: {file_name}")
					await bot.send_document(message.chat.id, document=open(decrypted_file_path, 'rb'), caption=f"Decrypted file: {file_name}")
					os.remove(decrypted_file_path) # Clean up temporary file
					
				except Exception as e:
					await bot.send_message(message.chat.id, "Wrong password")
					if os.path.exists(decrypted_file_path):
						os.remove(decrypted_file_path)
				
				# Delete the password message after operation completes
				try:
					await bot.delete_message(message.chat.id, password_message_id)
				except:
					pass
				
				waiting_for_password_download[user_id] = False
				del pending_download[user_id]
				return
	
	await bot.send_message(message.chat.id, f"File '{file_name}' not found.")
	
	# Delete the password message even if file not found
	try:
		await bot.delete_message(message.chat.id, password_message_id)
	except:
		pass
	
	waiting_for_password_download[user_id] = False
	del pending_download[user_id]


# Handle incoming files (documents, photos, audio, video). If the bot is not waiting for a file, it ignores the message.
@bot.message_handler(content_types=['document', 'photo', 'audio', 'video'])
async def handle_message(message):
	user_id = message.from_user.id

	# Verifies if the user is expected to send a file.
	if not waiting_for_file.get(user_id, False):
		return
	
	# Create download directory if it doesn't exist.
	save_dir = os.path.join(os.path.dirname(__file__), TEMPORARY_DIR_NAME)
	encrypted_dir = os.path.join(os.path.dirname(__file__), ENCRYPTED_DIR_NAME)
	os.makedirs(save_dir, exist_ok=True)
	os.makedirs(encrypted_dir, exist_ok=True)
	local_path = None
	file_name = None

	# Process the file based on the expected operation encryption.
	if waiting_for_operation.get(user_id) in ["encrypt_send", "encrypt_store"]:

		# If the received file is a document, download it. 
		if message.content_type == 'document':
			file_info = await bot.get_file(message.document.file_id)
			file_path = file_info.file_path
			file_name = message.document.file_name
			local_path = os.path.join(save_dir, file_name)
			file_data = await bot.download_file(file_path)
			with open(local_path, 'wb') as f:
				f.write(file_data)

		# If the received file is a photo, download it. 
		elif message.content_type == 'photo':
			# Download the highest resolution photo.
			photo = message.photo[-1]
			file_info = await bot.get_file(photo.file_id)
			file_path = file_info.file_path
			# Use the original name if it exists, otherwise use the file_id with the original file extension.
			if message.caption and message.caption.strip():
				file_name = message.caption.strip()
			else:
				# Try to preserve the original file extension.
				original_ext = os.path.splitext(file_info.file_path)[1]
				file_name = f"photo_{photo.file_id}{original_ext}"
			local_path = os.path.join(save_dir, file_name)
			file_data = await bot.download_file(file_path)
			with open(local_path, 'wb') as f:
				f.write(file_data)

		# If the received file is an audio file, download it.
		elif message.content_type == 'audio':
			file_info = await bot.get_file(message.audio.file_id)
			file_path = file_info.file_path
			if message.audio.file_name:
				file_name = message.audio.file_name
			else:
				# Try to preserve the original file extension.
				original_ext = os.path.splitext(file_info.file_path)[1]
				file_name = f"audio_{message.audio.file_id}{original_ext}"
			local_path = os.path.join(save_dir, file_name)
			file_data = await bot.download_file(file_path)
			with open(local_path, 'wb') as f:
				f.write(file_data)

		# If the received file is a video, download it.
		elif message.content_type == 'video':
			file_info = await bot.get_file(message.video.file_id)
			file_path = file_info.file_path
			if message.video.file_name:
				file_name = message.video.file_name
			else:
				# Try to preserve the original file extension.
				original_ext = os.path.splitext(file_info.file_path)[1]
				file_name = f"video_{message.video.file_id}{original_ext}"
			local_path = os.path.join(save_dir, file_name)
			file_data = await bot.download_file(file_path)
			with open(local_path, 'wb') as f:
				f.write(file_data)

		# If a valid file was downloaded proceed to encrypt it and rename the temp file to include the IV.
		# Finally, send the encrypted file back to the user or store it.
		if local_path and file_name:
			# Delete the original file message for security
			try:
				await bot.delete_message(message.chat.id, message.message_id)
			except:
				pass  # If deletion fails, continue anyway
			
			temp_output_file = local_path + ".temp"
			(key_256b, iv_128b) = encrypt_file(local_path, temp_output_file, user_passwords[user_id])
			if key_256b is None or iv_128b is None:
				await bot.send_message(message.chat.id, "Error during encryption.")
				# Clean up files
				os.remove(local_path)
				if os.path.exists(temp_output_file):
					os.remove(temp_output_file)
			else:
				# Encrypt and send the file to the user.
				if waiting_for_operation.get(user_id) == "encrypt_send":
					# For encrypt_send: encrypt and send, do not store
					enc_file = os.path.join(save_dir, file_name + "_iv" + iv_128b + ".enc")
					os.rename(temp_output_file, enc_file)
					final_output_file = enc_file
					await bot.send_message(message.chat.id, f"File encrypted. IV (128 bits): {iv_128b}")
					await bot.send_document(message.chat.id, document=open(final_output_file, 'rb'), caption="Encrypted file")
					# Clean up files
					os.remove(local_path)
					os.remove(final_output_file)

				# Encrypt and store the file in the encrypted directory.
				elif waiting_for_operation.get(user_id) == "encrypt_store":
					# For encrypt_store: encrypt and store, do not send
					final_output_file = os.path.join(encrypted_dir, file_name + "_iv" + iv_128b + ".enc")
					os.rename(temp_output_file, final_output_file)
					await bot.send_message(message.chat.id, f"File encrypted and stored. IV (128 bits): {iv_128b}")
					# Clean up original file
					os.remove(local_path)


		# If no valid file was found, notify the user. 
		else:
			await bot.send_message(message.chat.id, "File not valid")
			# Clean up any partial files
			if local_path and os.path.exists(local_path):
				os.remove(local_path)


	# Process the file based on the expected operation decryption.
	elif waiting_for_operation.get(user_id) == "decrypt":
		if message.content_type == 'document':
			file_info = await bot.get_file(message.document.file_id)
			file_path = file_info.file_path
			file_name = message.document.file_name
			local_path = os.path.join(save_dir, file_name)
			file_data = await bot.download_file(file_path)
			with open(local_path, 'wb') as f:
				f.write(file_data)
		
		if local_path and file_name:
			# Extract the IV from the filename.
			try:
				iv_hex = file_name.split("_iv")[-1].split(".enc")[0]
				iv = bytes.fromhex(iv_hex)
				if len(iv) != 16:
					raise ValueError("IV must be 16 bytes long")
			except Exception as e:
				await bot.send_message(message.chat.id, f"Error during IV extraction: {e}")
				# Clean up files
				if os.path.exists(local_path):
					os.remove(local_path)
				# Reset the waiting state for the user.
				waiting_for_file[user_id] = False
				waiting_for_operation[user_id] = None
				return

			# Decrypt the file.
			original_name = file_name.split("_iv")[0]
			output_file = os.path.join(save_dir, original_name)
			try:
				decrypt_file(user_passwords[user_id], iv, local_path, output_file)
				await bot.send_message(message.chat.id, "File decrypted successfully.")
				await bot.send_document(message.chat.id, document=open(output_file, 'rb'), caption="Decrypted file")
				# Clean up files
				os.remove(local_path)  # Remove encrypted file
				os.remove(output_file)  # Remove decrypted file after sending
			except Exception as e:
				await bot.send_message(message.chat.id, "Wrong password")
				# Clean up files even on error
				if os.path.exists(local_path):
					os.remove(local_path)
				if os.path.exists(output_file):
					os.remove(output_file)
		
		else:
			await bot.send_message(message.chat.id, "File not valid")
			# Clean up any partial files
			if local_path and os.path.exists(local_path):
				os.remove(local_path)
		

	# Reset the waiting state for the user.
	waiting_for_file[user_id] = False
	waiting_for_operation[user_id] = None
	if user_id in user_passwords:
		del user_passwords[user_id]
	
	# Delete the password message after operation completes
	if user_id in password_message_ids:
		try:
			await bot.delete_message(message.chat.id, password_message_ids[user_id])
		except:
			pass
		del password_message_ids[user_id]


# Padding function to ensure data is a multiple of 16 bytes.
def pad(data):
    padding_length = 16 - len(data) % 16
    padding = bytes([padding_length] * padding_length)
    return data + padding


# Unpadding function to remove padding from decrypted data.
def unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding encountered")
    return data[:-padding_length]


# Encrypts the input file and writes the encrypted data to the output file. Returns the hex-encoded key and IV.
def encrypt_file(input_file, output_file, key_plain):
    key = hashlib.sha256(key_plain.encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
		# Read the input file, pad the plaintext, and encrypt it.
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        padded_plaintext = pad(plaintext)
        ciphertext = cipher.encrypt(padded_plaintext)

		# Write the encrypted data to the output file.
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        encoded_key = key.hex()
        encoded_iv = iv.hex()
        return encoded_key, encoded_iv
	
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None, None
    

def decrypt_file(key_plain, iv, input_file, output_file):
    try:
        decoded_key = hashlib.sha256(key_plain.encode()).digest()
        
        if len(decoded_key) != 32:
            raise ValueError("Incorrect AES key length")
        cipher = AES.new(decoded_key, AES.MODE_CBC, iv)
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = unpad(cipher.decrypt(encrypted_data))
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
    except Exception as e:
        # Remove the output file if it was created
        if os.path.exists(output_file):
            os.remove(output_file)
        print(f"An error occurred during decryption: {e}")
        raise  # Re-raise the exception so it can be caught by the caller


async def main():
	print(">>> Bot iniciado...")
	await bot.polling()


if __name__ == "__main__":
	asyncio.run(main())
