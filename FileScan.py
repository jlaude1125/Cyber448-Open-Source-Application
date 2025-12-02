
def get_file_scan():
    # Prompt user for file path to scan
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': '9cf48fa4d97ddba0b7843b56261da3493bdb515f7d94b03d04a1fd04d00b2c8f'}
    #file_path = input('Enter the path to the file to be scanned: ')
    scan_result = None 
    

    # If successful, the scan results are printed; if there is an error, it is printed
    # Finally, the scan results are stored in a JSON file called data.json
    scan_result = None # Initialize scan_result to ensure it's defined for the finally block
    
    try:
        with open(file_path, 'rb') as file_to_scan:
            files = {'file': (os.path.basename(file_path), file_to_scan)}
            response = requests.post(url, files=files, params=params)
        
        if response.status_code == 200:
            scan_result = response.json()
            print(' Scan Request Successful:')
            print(scan_result)
        else:
            print(f' Error: HTTP Status Code {response.status_code}')
            print('Response Content:', response.text) # Print response text for debugging
    except FileNotFoundError:
        print(f' An error occurred: The file was not found at path: {file_path}')
    except Exception as e:
        print(' An unexpected error occurred:', str(e))
        
    finally:
        # This block attempts to write the result to a JSON file.
        # It should only run if the request was successful and scan_result is defined.
        if scan_result:
            output_file = 'data.json'
            data = []
            
            # 1. Read existing data (if file exists)
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as file:
                    try:
                        data = json.load(file)
                    except json.JSONDecodeError:
                        # If the file exists but is empty or corrupt, start with an empty list
                        print(f' Warning: {output_file} is corrupt or empty. Starting fresh list.')
                        data = []
            
            # 2. Append new result
            data.append(scan_result)
            
            # 3. Write all data back to the file
            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4, ensure_ascii=False)
            print(f'Data added to {output_file} successfully.')
        elif scan_result is not None:
             # This message handles the case where the request failed and scan_result is still None.
             print('JSON file not updated because the VirusTotal request failed.')


if __name__ == '__main__':
    get_file_scan()
