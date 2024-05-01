import aiohttp
import asyncio
import ssl
import logging
import urllib.parse

class AsyncPostRequestHandler:
    """
    A class to handle asynchronous POST requests to authenticate users. This class supports
    handling of HTTP redirections, logging successful and unsuccessful attempts, and managing
    SSL contexts for secure connections.
    This application leverages Python’s asyncio and aiohttp for efficient asynchronous network requests,
    allowing multiple operations to run concurrently without waiting for individual tasks to complete. 
    It uses an asyncio.Semaphore to manage up to 15 concurrent network operations, 
    preventing server overload and maintaining stability. 
    The event loop centralizes task management, 
    optimizing the execution and scheduling of tasks to enhance efficiency and minimize response times. 
    Operating in a single-threaded environment, 
    this asynchronous approach avoids the complexities of multithreading, 
    such as race conditions and deadlocks, making the application scalable, 
    easier to maintain, and ideal for I/O-bound operations like handling high volumes of network requests.
    
    This example may not be the most sophisticated method to demonstrate asynchronous I/O for network tasks,
    but it provides a simple and universally comprehensible approach. Login systems are relatively straightforward,
    as they are a common aspect of everyday life. The typical process involves locating the username field, 
    entering the username, locating the password field, entering the password, finding the submit button, clicking it,
    and verifying the success of the login. 
    However, contemporary login systems incorporate various security measures to mitigate potential abuse. 
    This code does not attempt to bypass any security measures, and should not be expected to nor was 
    ever intended to be used in ways that would be abused. 

    Thank you. 
    Upload Date May / 1st / 2024 
    

    https://github.com/johnniegreen/crawlspace/async_http_post_handler.py
    
    """
    def __init__(self):
        """
        Initializes the AsyncPostRequestHandler with default settings for SSL context
        and concurrency limits.
        """
        self.good_counter = 0  # Tracks the number of successful logins
        self.bad_counter = 0   # Tracks the number of failed logins
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.semaphore = asyncio.Semaphore(15)  # Limit to 15 concurrent tasks

    async def perform_login_request(self, session, username, password):
        """
        Performs the POST request for the login process and handles the response.
        """
        payload = {
            "user_box_field": username,
            "userpass_box_field": password,
            "submit_button_example": "Submit",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        login_url = "https://www.example.com/login"
        try:
            async with session.post(
                login_url, data=payload, headers=headers, ssl=self.ssl_context, timeout=30
            ) as response:
                if response.status == 200:
                    await self.handle_successful_response(username, response)
                else:
                    await self.log_unsuccessful_response(username, response)
        except aiohttp.ClientError as e:
            await self.handle_error(username, e)
        except asyncio.TimeoutError:
            logging.error(f"Timeout occurred for user {username}")

    async def handle_successful_response(self, username, response):
        """
        Handles the response for a successful login attempt.
        """
        self.good_counter += 1
        logging.info(f"Login successful for user {username}")
        await self.log_successful_attempt(username)

    async def log_unsuccessful_response(self, username, response):
        """
        Logs unsuccessful login attempts.
        """
        self.bad_counter += 1
        logging.warning(f"Login failed for user {username}")

    async def handle_error(self, username, error):
        """
        Handles any errors that occur during the login request.
        """
        logging.error(f"An error occurred for user {username}: {error}")
        logging.exception("Exception traceback:")

    async def log_successful_attempt(self, username):
        """
        Logs a successful login attempt to a file.
        """
        log_file_path = 'SuccessLogFile.log'
        with open(log_file_path, 'a') as file:
            file.write(f"Success #{self.good_counter} - Login - Username: {username}\n")

async def main():
    """
    Main function to execute the async login requests.
    """
    handler = AsyncPostRequestHandler()
    user_credentials = [('user1', 'password1'), ('user2', 'password2')]
    tasks = []

    for username, password in user_credentials:
        task = asyncio.create_task(handler.perform_login_request(None, username, password))
        tasks.append(task)

        if len(tasks) >= 10:
            await asyncio.gather(*tasks)
            tasks = []

    if tasks:
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
