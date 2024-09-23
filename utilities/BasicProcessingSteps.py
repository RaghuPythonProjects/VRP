from datetime import datetime, timedelta
import os
import pandas as pd
import numpy as np
import traceback
from utilities.logger_master import logger



def update_is_cisa_kev(data: pd.DataFrame, cisa_kev_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compare CVE IDs between the local data file and the CISA KEV file.
    """
    if len(cisa_kev_df) > 0:
        try:
            data['Vulnerability CVE IDs'] = data['Vulnerability CVE IDs'].fillna('')
            data['Vulnerability CVE IDs'] = data['Vulnerability CVE IDs'].str.upper()

            if 'cveID' not in cisa_kev_df.columns and 'CveID' in cisa_kev_df.columns:
                cisa_kev_df['cveID'] = cisa_kev_df['CveID']

            if 'cveID' in cisa_kev_df.columns:
                cisa_kev_df['cveID'] = cisa_kev_df['cveID'].str.upper()
                data['CisaKev'] = data['Vulnerability CVE IDs'].isin(cisa_kev_df['cveID'])
        except Exception as e:
            logger.error(f"An error occurred while comparing CVE IDs: {traceback.format_exc()}")

    return data

def update_cisa_kev_column_position(data: pd.DataFrame) -> pd.DataFrame:
    """
    Re-arrange columns such that CISA KEV related columns are placed after the 'Vulnerability CVSS Score' column.
    """
    df_columns = data.columns.tolist()
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
        data = data[df_columns]
    
    return data

def filter_to_last_30_days(data: pd.DataFrame) -> pd.DataFrame:
    """
    Filters the data to only include entries from the last 30 days based on 'Vulnerability Test Date'.
    """
    target_date = datetime.today() - timedelta(days=30)
    data = data[data['Vulnerability Test Date'] >= target_date]
    logger.info('Filtered data to include only the last 30 days.')
    return data

def exclude_false_positive(data: pd.DataFrame) -> pd.DataFrame:
    """
    Excludes known false positives based on the 'Vulnerability Title' and 'Service Port' columns.
    """
    if set(('Vulnerability Title', 'Service Port')).issubset(data.columns):
        exclude_condition_1 = (data['Vulnerability Title'] == 'X.509 Certificate Subject CN Does Not Match the Entity Name')
        exclude_condition_2 = (data['Service Port'].astype('float64').astype('Int64') == 17472)
        data = data[~(exclude_condition_1 & exclude_condition_2)]
        logger.info('Excluded false positives.')
    else:
        logger.info(f"Skipped exclusion of false positives - missing columns 'Vulnerability Title', 'Service Port'.")

    return data

def filter_to_severity_7(data: pd.DataFrame, severity: int = 7) -> pd.DataFrame:
    """
    Filters data to only include vulnerabilities with CVSS score >= severity.
    """
    data = data[data['Vulnerability CVSS Score'] >= severity]
    logger.info(f"Filtered data by severity score: {severity}")
    return data

def update_remediation_deadline(data: pd.DataFrame, remediation_deadline_age_days: int=180) -> pd.DataFrame:
    """
    Updates the 'Remediation Deadline' column based on 'Vulnerability Age'.
    """
    if 'Vulnerability Age' in data.columns:
        data['age_temp'] = data['Vulnerability Age'].str.replace(' Days', '').str.replace(' Day', '').str.replace(',', '').astype('Int64')
        data['Remediation Deadline'] = data['age_temp'] - remediation_deadline_age_days
        data['Remediation Deadline'] = data['Remediation Deadline'].astype(str) + ' Days'
        data = data.drop(columns=['age_temp'])
    
    return data

def merge_severity_scores(data: pd.DataFrame) -> pd.DataFrame:
    """
    Merges CVSS v2 and v3 scores, prioritizing v3 scores, and removes the v3 score column.
    """
    data['Vulnerability CVSS Score'] = np.where(
        data['Vulnerability CVSSv3 Score'].ne(0),
        data['Vulnerability CVSSv3 Score'],
        data['Vulnerability CVSS Score']
    )
    data.drop('Vulnerability CVSSv3 Score', axis=1, inplace=True)
    return data

def score_to_severity(score: float) -> str:
    """
    In the column immediately after (Column G?)
    add a string label identifying the vulnerability as a "high" or
    "critical" severity for easy human readability and metrics sorting.
    """
    if score == 0:
        return "None"
    elif 0.1 <= score <= 3.9:
        return "Low"
    elif 4.0 <= score <= 6.9:
        return "Medium"
    elif 7.0 <= score <= 8.9:
        return "High"
    elif 9.0 <= score <= 10.0:
        return "Critical"
    return ""

def add_severity_column(data: pd.DataFrame, column_position: int = 6) -> pd.DataFrame:
    """
    Applies the score_to_severity function to the specified CVSS score column in the DataFrame
    and inserts a new severity level column at the desired position.
    
    :param data: DataFrame containing the vulnerability data.
    :param position: The position where the new column should be inserted.
    :return: DataFrame with the new severity column.
    """
    cvss_column = 'Vulnerability CVSS Score'
    severity_column = 'Vulnerability CVSSv3 Severity'

    if cvss_column in data.columns:
        data.insert(
            loc=column_position,
            column=severity_column,
            value=data[cvss_column].apply(score_to_severity)
        )
        logger.info(f"Inserted column '{severity_column}' at position {column_position}.")
    else:
        logger.warning(f"CVSS column '{cvss_column}' not found in data.")
    
    return data


def add_unique_id_column(data: pd.DataFrame) -> pd.DataFrame:
    """
    Add a column at the end that represents the unique ID of the vulnerability.
    In order words, a specific instance of a vulnerability on a specific asset.
    This is a concatenation of the asset name and the vulnerabilityID
    """
    data['Unique Vulnerability ID'] = data['Asset Names'] + ' ' + data['Vulnerability ID']
    return data

def merge_split_files_to_master_excel_file(merge_files_dict: list[dict], merge_data_path: str, 
                                           processed_data_path: str, today_date_str: str, merge_files_sheets: list = None):
    """
    Merges split files into a master Excel file by combining sheets from multiple Excel files.
    """
    logger.info("Merging split files into master report (if listed)...")

    # Iterate through each set of files and master file names to merge
    for merge_files_set in merge_files_dict:
        files_set = merge_files_set['files_set']
        master_file_name = merge_files_set['master_file_name']
        logger.info(f"Creating master file {master_file_name} with files: {files_set}")

        try:
            # Define the master file path
            master_file_path = os.path.join(merge_data_path, f"{master_file_name}{today_date_str}.xlsx")
            
            # Create an Excel writer for the master file
            with pd.ExcelWriter(master_file_path) as writer:
                # Iterate over the files in the set
                for idx, file_name in enumerate(files_set):
                    logger.info(f"Reading data from file {file_name}")
                    xl_file_path = os.path.join(processed_data_path, f"{file_name}{today_date_str}.xlsx")

                    # Check if the file exists before attempting to read
                    if not os.path.exists(xl_file_path):
                        logger.debug(f"Skipping {master_file_name} (file not found: {xl_file_path})")
                        continue

                    logger.info(f"File exists: {xl_file_path}")
                    
                    # Load the Excel file
                    xls = pd.ExcelFile(xl_file_path)
                    logger.info(f"File {file_name} has {len(xls.sheet_names)} sheets: {xls.sheet_names}")

                    # Iterate over the sheets in the file
                    for sheet_number, sheet_name in enumerate(xls.sheet_names, start=1):
                        logger.info(f"Processing sheet {sheet_name} (Sheet #{sheet_number}) from {file_name}")

                        try:
                            # Read the data from the specific sheet
                            data = pd.read_excel(xl_file_path, sheet_name=sheet_name)
                            logger.info(f"Data read successfully from {sheet_name}. Rows: {len(data)}")

                            # Generate new sheet name based on `merge_files_sheets` or default names
                            if merge_files_sheets and idx < len(merge_files_sheets):
                                base_sheet_name = merge_files_sheets[idx]
                            else:
                                base_sheet_name = sheet_name

                            # Handle cases with multiple sheets per file
                            new_sheet_name = f"{base_sheet_name}_{sheet_number}" if sheet_number > 1 else base_sheet_name

                            logger.info(f"Writing data to sheet {new_sheet_name} in the master file.")
                            
                            # Add the CISA KEV column if needed (optional, customize based on your logic)
                            data = update_cisa_kev_column_position(data)

                            # Write the dataframe to the master file
                            data.to_excel(writer, sheet_name=new_sheet_name, index=False)
                            logger.info(f"Data written to {new_sheet_name} in the master file.")

                        except Exception as e:
                            logger.error(f"Error reading sheet {sheet_name} from {file_name}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Failed to create master file {master_file_name} with files {files_set}, Error: {str(e)}")
