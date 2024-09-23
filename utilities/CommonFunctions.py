import math
import time
import os
import pandas as pd
import numpy as np
from utilities.logger_master import logger


def load_report_data(target_filename: str) -> pd.DataFrame:
    """
    Loads report data from a CSV file.
    """
    try:
        logger.info(f"Loading report data from {target_filename}")
        data = pd.read_csv(target_filename, dtype={
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
        data.fillna('', inplace=True)
        if 'Vulnerability Risk Score' in data.columns:
            data['Vulnerability Risk Score'] = data['Vulnerability Risk Score'].replace(',', '', regex=True)
            data['Vulnerability Risk Score'] = pd.to_numeric(data['Vulnerability Risk Score'], errors='ignore')

        # Convert date fields from string to datetime
        if 'Vulnerable Since' in data.columns:
            data['Vulnerable Since'] = pd.to_datetime(data['Vulnerable Since'], errors='ignore')
        if 'Vulnerability Test Date' in data.columns:
            data['Vulnerability Test Date'] = pd.to_datetime(data['Vulnerability Test Date'], errors='ignore')

    except Exception as e:
        logger.error(f"Error loading report data from {target_filename}: {str(e)}")
        data = pd.DataFrame()  # Return empty DataFrame on error

    return data

# Given a single dataframe, split it into several sheets
def split_dataframe(data: pd.DataFrame, max_sheet_rows:int=1048000) -> list:
    num_sheets = math.ceil(len(data) / max_sheet_rows)
    chunked_df = [data[i:i + max_sheet_rows] for i in range(0, len(data), max_sheet_rows)]
    logger.info(f"...calculated {num_sheets} sheets, generating {len(chunked_df)} dataframes...")
    # FIrst sheet is simply "Data", then second sheet is Data 2, then Data 3, etc.
    sheet_list = [("Data" + str(i + 1) if i else "Data", df) for i, df in enumerate(chunked_df)]
    return sheet_list

def publish_data_into_excel_file_with_sheets(excel_file_path:str, sheet_list: list[tuple[str, pd.DataFrame]]) -> None:
    """
    Write multiple sheets to an Excel file.

    Args:
        writer (pd.ExcelWriter): The Excel writer object to write sheets.
        sheet_list (list): A list of tuples where each tuple contains a sheet name and dataframe.
    """
    filename = os.path.basename(excel_file_path)
    logger.info("Building Excel file {}...".format(filename))
    try:
        # Excel file will be created with static filename
        with pd.ExcelWriter(excel_file_path) as writer:
            for sheet_name, data in sheet_list:
                logger.info(f"Adding sheet {sheet_name} (Count: {len(data.index)}) to file {filename}")
                data.to_excel(writer, sheet_name=sheet_name, index=False)
        logger.info("...finished building {}.\n".format(filename))
    except:
        logger.error("SKIPPING AS NO DATA {}.\n".format(filename))


def check_if_file_is_valid(target_filename):
    if os.path.exists(target_filename):
        file_size = os.path.getsize(target_filename)
        logger.info(f'file_size = {file_size}')
        return float(file_size) > float(0)
    else:
        return False

def check_if_file_downloaded_recently(target_filename):
    try:
        if check_if_file_is_valid(target_filename):
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
