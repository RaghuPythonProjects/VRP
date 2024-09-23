import os
import math
import time
import pandas as pd
import numpy as np
import requests
from datetime import datetime, timedelta
from urllib3.exceptions import InsecureRequestWarning
import traceback
from utilities.inventory_files_config import base_folder, max_sheet_rows, report_api_headers, \
    remediation_deadline_age_days, cisa_kev_file_path
from utilities.sharepoint_api import SharePointAPI
from utilities.logger_master import logger, log_function_entry_exit

# Disable warnings for insecure requests.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


@log_function_entry_exit(logger)
class VulnerabilityReportProcessor:
    def __init__(self, data: pd.DataFrame, cisa_kev_df: pd.DataFrame = None, cisa_kev_file_path: str = None,
                 severity: int = 7):
        self.data = data
        self.severity = severity
        self.quit_execution = False

        self.cisa_kev_df = cisa_kev_df if cisa_kev_df else self.load_cisa_kev_file(cisa_kev_file_path)
        self.today_date_str = datetime.now().strftime("-%Y-%m-%d")
        self.unknown_regions = [['OS'], ['Network'], ['Applications']]
        self.count = []  # Initialize an empty list to store count data
        self.all_workstations = pd.DataFrame()

    def load_cisa_kev_file(self, cisa_kev_file_path):
        if cisa_kev_file_path and os.path.exists(cisa_kev_file_path):
            logger.info(f'Load CISA KEV file from path: {cisa_kev_file_path}')
            return pd.read_csv(cisa_kev_file_path)
        else:
            logger.info(f'Creating dummy CISA KEV dataframe, cisa_kev_file_path: {cisa_kev_file_path}')
            return pd.DataFrame()


    def update_is_cisa_kev(self):
        """Compare CVE IDs between the local data file and the CISA key file"""
        if len(self.cisa_kev_df) > 0:
            try:
                self.data['Vulnerability CVE IDs'] = self.data['Vulnerability CVE IDs'].fillna('')
                self.data['Vulnerability CVE IDs'] = self.data['Vulnerability CVE IDs'].str.upper()
                if 'cveID' not in self.cisa_kev_df.columns and 'CveID' in self.cisa_kev_df.columns:
                    self.cisa_kev_df['cveID'] = self.cisa_kev_df['CveID']

                if 'cveID' in self.cisa_kev_df.columns:
                    self.cisa_kev_df['cveID'] = self.cisa_kev_df['cveID'].str.upper()
                    self.data['CisaKev'] = self.data['Vulnerability CVE IDs'].isin(self.cisa_kev_df['cveID'])
            except Exception as e:
                logger(f"An error occurred while comparing CVE IDs: {traceback.format_exc()}")

    # check this function required or not at the end
    def update_cisa_kev_column_position(self):
        df_columns = self.data.columns.tolist()
        cisa_columns = ['Vulnerability CVSS Score', 'Vulnerability CVSSv3 Severity', 'CisaKev']

        if 'Vulnerability CVSS Score' in df_columns:
            # find first column
            cvss_column_position = df_columns.index('Vulnerability CVSS Score')
            # remove columns
            for col in cisa_columns:
                df_columns.remove(col)
            # insert columns
            for col in reversed(cisa_columns):
                df_columns.insert(cvss_column_position, col)
            # set columns
            self.data = self.data[df_columns]

    def filter_to_last_30_days(self):
        # Figure out the date 30 days ago
        target_date = datetime.today() - timedelta(days=30)
        # Conditionally drops rows with a test date greater than 45 days old.
        self.data.drop(self.data[self.data['Vulnerability Test Date'] < target_date].index, inplace=True)
        logger.info('filtered data to exclude recent 30 days data')
        return self.data

    def exclude_false_positive(self):
        # conditions to exclude
        if set(('Vulnerability Title', 'Service Port')).issubset(self.data.columns):
            exclude_condition_1 = (self.data[
                                       'Vulnerability Title'] == 'X.509 Certificate Subject CN Does Not Match the Entity Name')
            exclude_condition_2 = (self.data['Service Port'].astype('float64').astype('Int64') == 17472)
            self.data = self.data[~(exclude_condition_1 & exclude_condition_2)]
            logger.info('excluded false positives')
        else:
            error_message = f"SKIPPED to exclude false positives - missing columns 'Vulnerability Title', 'Service Port' in data columns: {list(self.data.columns)}"
            logger.info(error_message)
        return self.data

    def filter_to_severity_7(self):
        # DONE: Consider removing hard-coded value for severity.
        # NOTE: Experimenting with a boolean value for sorting the vulnerability. We want v3 scores with a value of 0 to use for v2 score fallback.
        self.data.drop(self.data[self.data['Vulnerability CVSS Score'] < self.severity].index, inplace=True)
        logger.info(f'filtered data by severity score: {self.severity}')
        return self.data

    def update_remediation_deadline(self):
        if 'Vulnerability Age' in self.data.columns:
            self.data['age_temp'] = self.data['Vulnerability Age'].str.replace(' Days', '').str.replace(' Day',
                                                                                                        '').str.replace(
                ',', '').astype('Int64')
            self.data['Remediation Deadline'] = self.data['age_temp'] - remediation_deadline_age_days
            self.data['Remediation Deadline'] = self.data['Remediation Deadline'].astype(str) + ' Days'

            self.data = self.data.drop(columns=['age_temp'])
        return self.data

    def merge_severity_scores(self):
        # NOTE: Built using this strategy https://stackoverflow.com/questions/55498357/update-pandas-column-with-another-columns-values-using-loc
        self.data['Vulnerability CVSS Score'] = np.where(self.data['Vulnerability CVSSv3 Score'].ne(0),
                                                         self.data['Vulnerability CVSSv3 Score'],
                                                         self.data['Vulnerability CVSS Score'])
        # After the above step, delete the v3 row as it is no longer needed.
        self.data.drop('Vulnerability CVSSv3 Score', axis=1, inplace=True)

    def download_report_from_api(self, report_id, target_filename):
        # TODO: Implement date checking.
        # Fetches the latest report for the given id.

        try:
            url = f"https://vmo7222pa005.otis.com:3780/api/3/reports/{report_id}/history/latest/output"
            response = requests.request("GET", url, headers=report_api_headers, verify=False)
            print(
                f'{target_filename}, Reponse Status: {response.status_code}, content length: {len(str(response.content))}, content: {str(response.content)[:250]}')
            logger.info(
                f'Reponse Status: {response.status_code}, content length: {len(str(response.content))}, content: {str(response.content)[:250]}')
            with open(target_filename, "wb") as file:
                file.write(response.content)
        except Exception as e:
            logger.error(f"Failed to download report {report_id} file {target_filename} error: {str(e)}")
            self.skip_data_process = True

    def load_report_data(self, target_filename):
        if self.quit_execution or self.skip_data_process:
            return

        logger.info(f"load report data")
        self.data = pd.read_csv(target_filename, dtype={
            'Asset IP Address': 'str',
            'Asset Names': 'str',
            'Asset Location': 'str',
            'Vulnerability Title': 'str',
            'Vulnerability CVE IDs': 'str',
            'Vulnerability CVSSv3 Score': np.float64,
            'Vulnerability CVSSv2 Score': np.float64,
            # 'Vulnerability Risk Score': 'str',
            'Vulnerability Description': 'str',
            'Vulnerability Proof': 'str',
            'Vulnerability Solution': 'str',
            'Asset OS Version': 'str',
            'Asset OS Name': 'str',

            'Asset OS Family': 'str',
            'Vulnerability Age': 'str',
            'Vulnerable Since': 'str',
            'Vulnerability Test Date': 'str',
            'Vulnerability ID': 'str'
        }, low_memory=False)
        if self.data is None or len(self.data) == 0:
            logger.error(f"ERROR: No data could be constructed from : {target_filename}")
            return
        self.data.fillna('', inplace=True)
        if 'Vulnerability Risk Score' in self.data.columns:
            # Convert 'Vulnerability Risk Score' removing commas and converting to float.
            self.data['Vulnerability Risk Score'] = self.data['Vulnerability Risk Score'].replace(',', '', regex=True)
            self.data['Vulnerability Risk Score'] = pd.to_numeric(self.data['Vulnerability Risk Score'],
                                                                  errors='ignore')
        # Convert date fields from string to datetime.

        if 'Vulnerable Since' in self.data.columns:
            self.data['Vulnerable Since'] = pd.to_datetime(self.data['Vulnerable Since'], errors='ignore')
        if 'Vulnerability Test Date' in self.data.columns:
            self.data['Vulnerability Test Date'] = pd.to_datetime(self.data['Vulnerability Test Date'], errors='ignore')

    # Takes a dataframe and performs all the typical process steps on it.
    def perform_standard_processing(self):
        # Every single file is filtered for the last 30 days
        self.exclude_false_positive()
        self.filter_to_last_30_days()
        self.merge_severity_scores()
        # New addition: Add a column for severity level (critical, high, etc).
        # Every single filedis filtered to have only CVSSv3 Severity 7 or Higher.
        self.filter_to_severity_7()

        self.update_is_cisa_kev()

        # self.update_remediation_deadline() # Commented since dates are corrupted in db
        def score_to_severity(x):
            # In the column immediately after (Column G?)
            # add a string label identifying the vulnerability as a "high" or
            # "critical" severity for easy human readability and metrics sorting.
            if x == 0:
                return "None"
            elif 0.1 <= x <= 3.9:
                return "Low"
            elif 4.0 <= x <= 6.9:
                return "Medium"
            elif 7.0 <= x <= 8.9:
                return "High"
            elif 9.0 <= x <= 10.0:
                return "Critical"
            return ""

        # The above method destroys the v3 column and overwrites the non-zero v3 values into a single "CVSS score" column. With that
        # created, we then assign the Criticality tags.

        self.data.insert(loc=6, column='Vulnerability CVSSv3 Severity',
                         value=self.data['Vulnerability CVSS Score'
                         ].apply(score_to_severity))
        # Add a column at the end that represents the unique ID of the vulnerability.
        # In order words, a specific instance of a vulnerability on a specific asset.
        # This is a concatenation of the asset name and the vulnerabilityID
        self.data['Unique Vulnerability ID'] = self.data['Asset Names'] + ' ' + self.data['Vulnerability ID']
        self.data.fillna('', inplace=True)  # Remove any empty entries

    # For all operating system files, they will be split between Workstations and Servers
    def process_os(self):
        logger.info("Filtering applied: OS criteria")
        # Workstation

        workstation_criteria = self.data['Asset OS Name'].str.contains('Microsoft Windows 1') & \
                               self.data['Asset OS Version'].str.startswith('2')
        work = self.data[workstation_criteria]
        # Server - includes blanks
        server_criteria = ~(self.data['Asset OS Name'].str.contains('Microsoft Windows') |
                            self.data['Asset OS Name'].str.contains('ROUTER') |
                            self.data['Asset OS Name'].str.contains('RT') |
                            self.data['Asset OS Name'].str.contains('NETWORK')) | \
                          self.data['Asset OS Name'].str.contains('Microsoft Windows Server')
        server = self.data[server_criteria]
        return ['Workstations', 'Servers'], [work, server]

    def process_network(self):
        logger.info("Filtering applied: Network criteria")
        # network = data[~data['Asset OS Name'].str.contains('Windows')]

        # return ['Network'], [network]
        return ['Network'], [self.data]

    def process_app(self):
        logger.info("Filtering applied: Applications criteria")
        app = self.data[~(self.data['Vulnerability ID'].str.contains('msft-cve') |
                          self.data['Vulnerability ID'].str.contains('mssql-obsolete') |
                          self.data['Vulnerability ID'].str.contains('windows-10-obsolete') |
                          self.data['Vulnerability ID'].str.contains('snmp'))]
        return ['Applications'], [app]

    # NOTE: Keeping method for later review.
    def process_uc(self):
        logger.info("Processing UC")
        uc_criteria = ~(
                    self.data['Asset Names'].str.contains('mersive') | self.data['Asset Names'].str.contains('Mersive'))
        self_criteria = self.data['Vulnerability ID'].str.contains('ssl-self-signed-certificate')
        uc = self.data[uc_criteria & ~self_criteria]

        _self = self.data[self_criteria & uc_criteria]
        return ['UC', 'Self-signed'], [uc, _self]

    def process_region(self, data, category, region, region_to_exclude=None):
        logger.info(f"Filtering applied: {region} criteria")
        category_mapping = {'Workstations': 0, 'Servers': 0, 'Network': 1, 'Applications': 2}
        if category not in category_mapping:
            logger.debug(f"unidentified category '{category}'...")
            valid_category = False
        else:
            valid_category = True
        # Define region-specific conditions
        region_condition = data['Asset Location'].str.contains(region)
        if region_to_exclude:
            logger.info(f"filter data for region: '{region}'...")
            logger.info(f"exclude data for region: '{region_to_exclude}'...")
            exclude_condition = data['Asset Location'].str.contains(region_to_exclude)
            exclude_data = data[exclude_condition]

            region_data = data[region_condition & ~exclude_condition]
        else:
            logger.info(f"filter data for region: '{region}'...")
            exclude_data = []
            region_data = data[region_condition]
        if valid_category:
            logger.info(f"update 'other' data for category: '{category}'...")
            other_data = data[~region_condition]
            # Manage unknown regions as per new_file type
            target_index = category_mapping[category]

            # Updating unknown regions
            if len(self.unknown_regions[target_index]) == 1:
                self.unknown_regions[target_index].append(other_data)
            else:
                self.unknown_regions[target_index][1] = pd.concat([self.unknown_regions[target_index][1], other_data])
        region_to_exclude = 'WHQ' if region_to_exclude == 'site:000677' else region_to_exclude
        # Output files and data
        if region_to_exclude:
            return [f'{region}-{category}', f'{region_to_exclude}-{category}'], [region_data, exclude_data]
        else:
            return [f'{region}-{category}'], [region_data]

    def run_standard_report_process_steps(self):
        if self.filename in ('AMER - OS', 'EMEA - OS', 'APAC - OS'):
            new_file, data = self.process_os()
            # data is a list of dataframes (equivalent to vector<DataFrame>)

            # new_file is a list of names, i.e. 'workstations', 'servers' (equivalent to vector<string>)
        elif self.filename in ('AMER - Network', 'EMEA - Network', 'APAC - Network'):
            new_file, data = self.process_network()
            if self.filename in ('AMER - Network'):
                logger.info(f'AMER - Network - new_file  {new_file}')
                logger.info(f'AMER - Network - data  {data}')
        elif self.filename in ('AMER - Applications', 'EMEA - Applications', 'APAC - Applications'):
            new_file, data = self.process_app()
        # TODO: Are these needed? New file string name may be required
        elif self.filename in (
        'UC', 'CGI - OS', 'CGI - Applications', 'DXC - OS', 'DXC - Applications', 'DXC', 'Synology',
        "Externally Facing - HK VoIP", "DXC - DMZ"):
            new_file, data = [self.filename], [self.data]
        else:

            logger.error(f"Category '{self.filename}' not recognized - SKIP PROCESSING")
            return
        region = None
        region_to_exclude = None
        if 'AMER' in self.filename:
            region = 'AMER'
            region_to_exclude = 'site:00677'
        elif 'APAC' in self.filename:
            region = 'APAC'
            region_to_exclude = 'CN'
        elif 'EMEA' in self.filename:
            region = 'EMEA'
        # TODO: Patchwork to keep from needing to rework logic.
        elif 'UC' in self.filename or 'CGI' in self.filename or 'DXC' in self.filename or 'Synology' in self.filename or 'VoIP' in self.filename:
            new_file, data = [new_file], [data]
        else:
            logger.error(f"Region '{self.filename}' not recognized - SKIP PROCESSING")
            return

        if region:
            # TODO: Patchwork to keep from needing to rework logic.
            # data becomes a list of lists (2D vector) (equivalent to vector<vector<DataFrame>>)
            # data[i] is a list of two dataframes (AMER and WHQ)
            # new_file is a list of lists of names (equivalent to vector<vector<string>>)
            for idx, _ in enumerate(data):
                new_file[idx], data[idx] = self.process_region(data=data[idx], category=new_file[idx],
                                                               region=region, region_to_exclude=region_to_exclude)
                logger.info(f'process_region - new_file={new_file[idx]}, data={len(data[idx])}')
        data = self.process_and_record_data(new_file, data)
        self.process_final_file(new_file, data)

    def process_and_record_data(self, new_file, data):
        for i in range(len(data)):
            for j in range(len(data[i])):

                dedup = data[i][j].drop_duplicates()
                row_diff = len(data[i][j].index) - len(dedup.index)
                logger.info(
                    f"{new_file[i][j]}: Out of {len(data[i][j].index)} total entries, {row_diff} duplicates were detected and removed. {len(dedup.index)} unique values remain.")
                # We don't need count data for secondary files.
                if 'UC' in new_file[i][j] or 'CGI' in new_file[i][j] \
                        or 'DXC' in new_file[i][j] or 'Synology' in new_file[i][j] \
                        or 'WHQ-Servers' in new_file[i][j]:
                    continue
                # Record the count for everything else.
                # DONE: Try-catch shouldn't be used as a fallback.
                # TODO: Maybe rework how value_counts is used for examine dedup further?
                crit_count = dedup['Vulnerability CVSSv3 Severity'].value_counts().get('Critical', 0)

                high_count = dedup['Vulnerability CVSSv3 Severity'].value_counts().get('High', 0)
                # Log count data
                logger.info(f"Adding to Count: [{new_file[i][j]}, {crit_count}, {high_count}, {len(dedup.index)}]")
                self.count.append([new_file[i][j], crit_count, high_count, len(dedup.index)])
                data[i][j] = dedup  # Replace the original DataFrame with the deduplicated DataFrame
                logger.info(f'final data length = {len(data[i][j])}')
        return data

    def process_final_file(self, new_file, data):
        logger.info("Writing contents to file...")
        base_filename = 'Weekly Report'
        categories = {
            'Workstations': 'Operating Systems - ',
            'Servers': 'Operating Systems - ',
            'CGI - Applications': 'CGI - Applications - Weekly Report',

            'Network': 'Network - ',
            'UC': 'UC - Weekly Report',
            'CGI - OS': 'CGI - OS - Weekly Report',
            'DXC - OS': 'DXC - OS - Weekly Report',
            'DXC - Applications': 'DXC - Applications - Weekly Report',
            'DXC - DMZ': 'DXC - DMZ',
            'DXC': 'DXC - Weekly Report',
            'Synology': 'Synology - Weekly Report',
            'VoIP': 'Externally Facing - HK VoIP'
        }
        region_prefix = {
            'AMER': 'AMER and WHQ',
            'WHQ': 'AMER and WHQ',
            'APAC': 'APAC and CN',
            'CN': 'APAC and CN',
            'EMEA': 'EMEA'

        }
        # TODO: Consider adding dates to these.
        if ('Applications' in new_file[0][0]) & ('CGI' not in new_file[0][0]) & ('DXC' not in new_file[0][0]):
            filename = 'Applications - '
        else:
            category = next((cat for cat in categories if cat in new_file[0][0]), None)
            filename = categories.get(category, '')
            if filename == '':
                logger.info(f'Category unrecognized {new_file[0][0]}')
        # Append region if applicable
        region = next((reg for reg in region_prefix if reg in new_file[0][0]), None)
        filename += region_prefix.get(region, '')
        # Define the Excel filename
        excel_filename = filename + self.today_date_str + '.xlsx'

        logger.info(
            f"Output path: {self.processed_data_path} \t Filename: {filename} \t Join: {os.path.join(self.processed_data_path, filename)}")
        # Exporting to Excel file with multiple sheets, and handling large datasets by exporting to CSV if necessary
        try:
            excel_file_path = os.path.join(self.processed_data_path, excel_filename)
            with pd.ExcelWriter(excel_file_path) as writer:
                for i, file_group in enumerate(new_file):
                    logger.info(f'file_group : {file_group}')
                    for j, sheet_name in enumerate(file_group):
                        logger.info(f'sheet_name : {sheet_name}')
                        logger.info(data[i][j].head())
                        if len(data[i][j]) > 0:
                            try:
                                if 'Workstations' in sheet_name:  # add dataframe to 'all workstations'

                                    if self.all_workstations.empty:
                                        self.all_workstations = data[i][j]
                                    else:
                                        self.all_workstations = pd.concat([self.all_workstations, data[i][j]])

                                data[i][j].to_excel(writer, sheet_name=new_file[i][j], na_rep='', index=False)
                                logger.info(f"...finished processing {sheet_name}. Saved as {excel_filename}")
                            except ValueError as ve:
                                # INFO: Fallback to save as CSV if failed to save data as Excel file
                                # DONE: Consider splitting the file into two excel sheets rather than csv
                                logger.info("Splitting original dataframe into sheets if needed...")

                                sheets_list = self.split_dataframe(data[i][j])
                                self.publish_data_into_excel_file_with_sheets(filename, sheets_list)
                                # csv_filename = filename.replace(' - ', ' ') + '.csv'
                                # data[i][j].to_csv(os.path.join(self.processed_data_path, csv_filename), na_rep='', index=False)
                                logger.error(
                                    f"{ve}\n...Unable to write to Excel due to row count. Converting to .csv file(s) instead.")
                                logger.info(f"...finished processing {sheet_name}. Saved as {filename}")
                        else:
                            logger.error(f"...EMPTY DF SKIPPED {sheet_name}. Saved as {filename}")
        except Exception as e:
            logger.error(
                f"Failed to create file Filename: {filename} \t Join: {os.path.join(self.processed_data_path, filename)}")

        except Exception as e:
            logger.error(
                f"Failed to create file Filename: {filename} \t Join: {os.path.join(self.processed_data_path, filename)}")

    def process_all_workstations_unknownregions(self):
        # all workstations
        logger.info('Generating all_workstations files ...')
        if not self.all_workstations.empty:
            logger.info("Splitting all_workstations dataframe into sheets if needed...")
            sheets_list = self.split_dataframe(self.all_workstations)
            self.publish_data_into_excel_file_with_sheets('All Workstations', sheets_list)
            # self.all_workstations.to_excel(os.path.join(self.processed_data_path, f'All Workstations{self.today_date_str}.xlsx'), index=False)
        # export unknown_regions - separate excel sheets
        logger.info('Generating Unknown Region files ...')

        # TODO: Zip the unknown_regions files into one location.
        for i in range(len(self.unknown_regions)):
            if len(self.unknown_regions[i]) > 1:  # makes sure there are actually entries
                base_filename = 'Unknown regions - {}'.format(self.unknown_regions[i][0])
                if len(self.unknown_regions[i][1]) > 0:
                    sheets_list = self.split_dataframe(self.unknown_regions[i][1])
                    self.publish_data_into_excel_file_with_sheets(base_filename, sheets_list)
                else:
                    logger.info(f'... EMPTY DF SKPIIED, base_filename: {base_filename}')
        # export count to Excel file
        logger.info('\nGenerating Total Count file ...')
        count_df = pd.DataFrame(self.count, columns=['File', 'Critical', 'High', 'Total'])
        # Sort to match order of weekly tracker spreadsheet.
        count_df.sort_values('File')

        logger.info("Splitting count_df dataframe into sheets if needed...")
        sheets_list = self.split_dataframe(count_df)
        self.publish_data_into_excel_file_with_sheets('Total Count', sheets_list)
        # count_df.to_excel(os.path.join(self.processed_data_path, f'Total Count{self.today_date_str}.xlsx'), index=False)
        logger.info('...finished processing Total Count.xlsx')

    # Processes the list of files (workstation OS, sever applications, etc.) with the intent of
    # stitching them into a single file.
    def publish_data_into_excel_file_with_sheets(self, filename, sheet_list):
        logger.info("Building Excel file {}...".format(filename))
        try:
            # Excel file will be created with static filename
            excel_file_path = os.path.join(self.processed_data_path, filename + self.today_date_str + ".xlsx")
            with pd.ExcelWriter(excel_file_path) as writer:

                for sheet_name, data in sheet_list:
                    logger.info(f"Adding sheet {sheet_name} (Count: {len(data.index)}) to file {filename}")
                    data.to_excel(writer, sheet_name=sheet_name, index=False)
            logger.info("...finished building {}.\n".format(filename))
        except:
            logger.error("SKIPPING AS NO DATA {}.\n".format(filename))

    def publish_data_into_excel_file(self, file):
        # Processing an individual file into an excel spreadsheet.
        sheet_name = 'Data'
        logger.info(f"Building Excel file {self.filename}...")

        try:
            excel_file_path = os.path.join(self.processed_data_path, self.filename + self.today_date_str + ".xlsx")
            with pd.ExcelWriter(excel_file_path) as writer:
                file.to_excel(writer, sheet_name=sheet_name, index=False)
        except Exception as e:
            logger.error("SKIPPING AS NO DATA {}.\n".format(self.filename))
        logger.info("...finished processing {}.\n".format(self.filename))

    # merge HI - OS and Application files into single Excel File
    def merge_split_files_to_master_excel_file(self):
        if self.quit_execution:
            logger.debug("======= SKIPPING MERGE FILEs - quit_execution triggered")
            return None
        if len(self.merge_files_dict) == 0:
            logger.debug("======= SKIPPING MERGE FILEs - merge_files_dict is missing")
            return None
        if not self.merge_data_folder:
            logger.debug("======= SKIPPING MERGE FILEs - merge_data_folder is not mentioned")
            return None
        logger.info("Merge split files to master report (if listed)...")
        for merge_files_set in self.merge_files_dict:
            files_set = merge_files_set['files_set']
            master_file_name = merge_files_set['master_file_name']
            logger.info(f"Creating master file {master_file_name} (with: {files_set})")
            try:
                excel_file_path = os.path.join(self.merge_data_path, master_file_name + self.today_date_str + ".xlsx")
                with pd.ExcelWriter(excel_file_path) as writer:
                    for idx, file_name in enumerate(files_set):
                        logger.info(f"Read data from file {file_name}")
                        xl_file_path = os.path.join(self.processed_data_path, file_name + self.today_date_str + ".xlsx")

                        logger.info(f"Read data from file path {xl_file_path}")
                        if not os.path.exists(xl_file_path):
                            logger.debug(
                                f"======= SKIPPING master file {master_file_name} (missing file: {xl_file_path})")
                            continue
                        logger.info(f"File Exists {xl_file_path}")
                        xls = pd.ExcelFile(xl_file_path)
                        for sheet_number, sheet_name in enumerate(xls.sheet_names, start=1):
                            logger.info(f'xl_file_path, IDX: {sheet_number}, Name:{sheet_name}')
                            try:
                                self.data = pd.read_excel(xl_file_path, sheet_name=sheet_name)
                                logger.info(self.data)
                            except Exception as e:
                                logger.error(str(e))
                            # assing sheet name from config if isted

                            _sheet_name = self.merge_files_sheets[idx] if idx < len(
                                self.merge_files_sheets) else f'{sheet_name}_{idx}'
                            new_sheet_name = f'{_sheet_name}_{sheet_number}' if sheet_number > 1 else _sheet_name
                            logger.info(f"add data to sheet {new_sheet_name} - START")
                            self.update_cisa_kev_column_position()
                            self.data.to_excel(writer, sheet_name=new_sheet_name, index=False)
                            logger.info(f"add data to sheet {new_sheet_name} - END")
            except Exception as e:
                logger.error(f"Failed to create master file {master_file_name} (with: {files_set}), ERROR: {str(e)}")

    # Given a single dataframe, split it into several sheets
    def split_dataframe(self, data_df):
        num_sheets = math.ceil(len(data_df) / max_sheet_rows)

        chunked_df = [data_df[i:i + max_sheet_rows] for i in range(0, len(data_df), max_sheet_rows)]
        logger.info(f"...calculated {num_sheets} sheets, generating {len(chunked_df)} dataframes...")
        # FIrst sheet is simply "Data", then second sheet is Data 2, then Data 3, etc.
        self.sheet_list = [("Data" + str(i + 1) if i else "Data", df) for i, df in enumerate(chunked_df)]
        return self.sheet_list

    def check_data_status(self, tag=''):
        if self.quit_execution:
            return 'QUIT'
        elif self.skip_data_process:
            return 'SKIP'
        elif len(self.data) == 0 and self.merge_files_dict and self.merge_data_folder:
            logger.error(f"Data is empty for file: {self.filename} : {tag}")
            logger.error(f"quit execution!")
            self.quit_execution = True
            return 'QUIT'
        elif len(self.data) == 0:

            logger.error(f"Data is empty for file: {self.filename} : {tag}")
            self.quit_execution = False
            return 'SKIP'
        else:
            self.quit_execution = False
            return 'CONTINUE'

    def check_if_file_is_valid(self, target_filename):
        if os.path.exists(target_filename):
            file_size = os.path.getsize(target_filename)
            logger.info(f'file_size = {file_size}')
            return float(file_size) > float(0)
        else:
            return False

    def check_if_file_downloaded_recently(self, target_filename):
        try:
            if self.check_if_file_is_valid(target_filename):
                mod_time = os.path.getatime(target_filename)
                age_hrs = int((time.time() - mod_time) / 3600)
                if age_hrs <= 4:
                    return True
                else:
                    return False

            else:
                return False
        except Exception as e:
            logger.debug(f'unable to read file timestamp - {e}')
        return False

    def download_reports(self):
        for self.report_id, self.filename in self.report_dict.items():
            try:
                self.quit_execution = False
                self.skip_data_process = False
                if not self.filename or (self.filename and len(self.filename) == ''):
                    logger.error(f"Unable to determine filename for given report ID: {self.report_id}")
                    continue

                # Download the equivalent report to a dataframe
                target_filename = os.path.join(self.raw_data_path, self.filename + ".csv")
                if not self.check_if_file_downloaded_recently(target_filename):
                    logger.info(f"Generating dataframe for {self.filename}...")

                    self.download_report_from_api(self.report_id, target_filename)
                    logger.info(f"...done generating.")
                else:
                    logger.info(f"file already downloaded proceed with processing {self.filename}...")

            except Exception as e:
                logger.error(f"Error processing report {self.filename}: {str(e)}")
                continue

    def process_reports(self):
        for file_name in os.listdir(self.raw_data_path):
            logger.info(f'process report start - {file_name}')
            try:
                self.quit_execution = False
                self.skip_data_process = False
                target_filename = os.path.join(self.raw_data_path, file_name)
                target_filename_asset_count = os.path.join(self.raw_data_path,
                                                           file_name.split('.')[0] + '_assets_count.csv')
                if not self.check_if_file_is_valid(target_filename):
                    logger.error(f"...EMPTY FILE SKIPPED. filename {self.filename}")
                    continue
                logger.info(f'process report target_filename - {target_filename}')
                self.filename = file_name.split('.')[0]
                self.load_report_data(target_filename)
                logger.info(f'process report check status - {target_filename}')
                # check if data processing steps needs to be skipped
                data_status = self.check_data_status()
                # QUIT: if data is empty and merge files is needed
                if data_status == 'QUIT':
                    return
                # SKIP: if data is empty and merge files is not needed
                elif data_status == 'SKIP':
                    continue
                logger.info(
                    f'process report perform_standard_processing - filename: {self.filename}, target: {target_filename}')

                # Execute standard processing steps (merge severity scores, assign severity labels, etc.)
                self.perform_standard_processing()
                logger.info(
                    f'process report update_cisa_kev_column_position - filename: {self.filename}, target: {target_filename}')
                self.update_cisa_kev_column_position()
                print('create target_filename_asset_count', target_filename_asset_count)
                tmp_data = self.data.copy()
                tmp_data = tmp_data.groupby('Asset Names').size().reset_index(name='asset_count').to_csv(
                    target_filename_asset_count, index=False)
                print('create target_filename_asset_count Completed')

                if self.report_name == 'Standard':
                    logger.info(
                        f"Start standard report processing... - filename: {self.filename}, target: {target_filename}")
                    self.run_standard_report_process_steps()

                else:
                    # continue with processing.
                    logger.info(
                        f"Splitting original dataframe into sheets if needed... - filename: {self.filename}, target: {target_filename}")
                    if len(self.data) > 0:
                        sheets_list = self.split_dataframe(self.data)
                        self.publish_data_into_excel_file_with_sheets(self.filename, sheets_list)
                    else:
                        logger.error(f"...EMPTY DF SKIPPED. filename {self.filename}")
            except Exception as e:
                logger.error(f"Error processing report {self.filename}: {str(e)}")
                continue

    def get_history_folder_path(self):
        logger.info(
            f'history_folder_path = {self.history_folder_path}, history_folder_name = {self.history_folder_name}')
        if self.history_folder_path and self.history_folder_name:

            now = datetime.now()
            current_monday = now - timedelta(days=now.weekday())
            target_date = current_monday.strftime("%Y-%m-%d")
            target_year = current_monday.year
            return f"{self.history_folder_path}/{target_year}/{target_date}/{self.history_folder_name}"
        else:
            return None

    def get_latest_folder_path(self):
        logger.info(f'latest_folder_path = {self.latest_folder_path}, latest_folder_path = {self.latest_folder_path}')
        if self.latest_folder_path and self.latest_folder_path:
            return f"{self.latest_folder_path}/{self.latest_folder_name}"
        else:
            return None

    def get_report_paths_from_folder(self, folder):
        path_to_folder = os.path.join(os.getcwd(), folder)
        report_paths = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder)]
        logger.info(f"found {len(report_paths)} files in folder {folder}")

        return report_paths

    def get_reports_to_push_to_sharepoint(self):
        logger.info('get report paths to push to sharepoint')
        if self.merge_data_folder and self.merge_files_dict:
            report_paths = self.get_report_paths_from_folder(self.merge_data_path)
        else:
            report_paths = self.get_report_paths_from_folder(self.processed_data_path)
        return report_paths

    def upload_to_sharepoint(self):
        if self.quit_execution:
            logger.debug("======= SKIPPING PUSH TO SHAREPOINT - quit_execution is triggered")
            return None
        latest_folder = self.get_latest_folder_path()
        history_folder = self.get_history_folder_path()
        if not latest_folder and not history_folder:
            logger.debug("======= SKIPPING PUSH TO SHAREPOINT - no mention of latest or history folder paths")
            return None
        report_paths = self.get_reports_to_push_to_sharepoint()
        if len(report_paths) == 0:
            logger.debug("======= SKIPPING PUSH TO SHAREPOINT - no files in report folder")
            return None
        logger.info('upload_to_sharepoint - START')
        sharepoint_api = SharePointAPI()
        if latest_folder:
            logger.info(f'upload_to_sharepoint folder {latest_folder}')
            sharepoint_api.publish_files(folder=latest_folder, reports=report_paths)
        if history_folder:
            logger.info(f'upload_to_sharepoint folder {history_folder}')
            sharepoint_api.publish_files(folder=history_folder, reports=report_paths)

    def manage_reports(self):

        logger.info(f"START OF EXECUTION FOR REPORT - {self.report_name}")
        if self.download_new_reports:
            logger.info("Downloading new reports...")
            self.download_reports()
            logger.info("processing new reports...")
            self.process_reports()
            if self.report_name == 'Standard':
                self.process_all_workstations_unknownregions()
            self.merge_split_files_to_master_excel_file()
        else:
            logger.info("Bypassing download of new reports. Continuing the publication step.")
        # self.upload_to_sharepoint()
        logger.info(f"END OF EXECUTION FOR REPORT - {self.report_name}")
        # TODO: Delete the local files once finished?

    def run(self):
        self.manage_reports()
