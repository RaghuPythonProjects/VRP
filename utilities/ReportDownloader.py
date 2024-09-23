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
        """
        try:
            url = f"https://vmo7222pa005.otis.com:3780/api/3/reports/{report_id}/history/latest/output"
            response = requests.request("GET", url, headers=self.report_api_headers, verify=False)
            logger.info(
                f"Downloading report {report_id}, Response Status: {response.status_code}, "
                f"content length: {len(str(response.content))}, content: {str(response.content)[:250]}"
            )

            # Save the content to the file
            with open(target_filename, "wb") as file:
                file.write(response.content)

            logger.info(f"Report {report_id} saved to {target_filename}")
            return True

        except Exception as e:
            logger.error(f"Failed to download report {report_id} to {target_filename}, error: {str(e)}")
            logger.error(traceback.format_exc())
            return False
