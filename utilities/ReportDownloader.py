import os
import requests
from utilities.logger_master import logger
from urllib3.exceptions import InsecureRequestWarning
import traceback

# Disable warnings for insecure requests.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class ReportDownloader:
    def __init__(self, report_api_headers):
        self.report_api_headers = report_api_headers

    def download_report_from_api(self, report_id, target_filename):
        """
        Download the latest report for the given report ID and save it to the specified target filename.
        Uses streaming to handle large files.
        """
        try:
            url = f"https://vmo7222pa005.otis.com:3780/api/3/reports/{report_id}/history/latest/output"
            
            # Use streaming for downloading large files
            with requests.get(url, headers=self.report_api_headers, verify=False, stream=True) as response:
                response.raise_for_status()  # Raise an error if the request failed
                total_size = response.headers.get('content-length')

                logger.info(
                    f"Downloading report {report_id}, Response Status: {response.status_code}, "
                    f"content length: {total_size if total_size else 'unknown'}"
                )

                # Save the content to the file in chunks
                with open(target_filename, "wb") as file:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):  # 1 MB chunks
                        if chunk:  # Filter out keep-alive new chunks
                            file.write(chunk)

            logger.info(f"Report {report_id} successfully saved to {target_filename}")
            return True

        except Exception as e:
            logger.error(f"Failed to download report {report_id} to {target_filename}, error: {str(e)}")
            logger.error(traceback.format_exc())
            return False
