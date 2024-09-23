from datetime import datetime, timedelta
import math
import os
import pandas as pd
import numpy as np
import traceback
from utilities.logger_master import logger
from utilities import CommonFunctions

def run_standard_report_process_steps(filename: str, data: pd.DataFrame, unknown_regions: list, 
                                      processed_data_path: str, today_date_str: str, all_workstations: pd.DataFrame,
                                      count:list=[]) -> tuple[list, list]:
    """
    Run standard report process steps based on the file type.
    """
    if filename in ('AMER - OS', 'EMEA - OS', 'APAC - OS'):
        new_file, data = process_os(data)
        # data is a list of dataframes (equivalent to vector<DataFrame>)
        # new_file is a list of names, i.e. 'workstations', 'servers' (equivalent to vector<string>)
    elif filename in ('AMER - Network', 'EMEA - Network', 'APAC - Network'):
        new_file, data = process_network(data)
    elif filename in ('AMER - Applications', 'EMEA - Applications', 'APAC - Applications'):
        new_file, data = process_app(data)
    # TODO: Are these needed? New file string name may be required
    elif filename in ('UC', 'CGI - OS', 'CGI - Applications', 'DXC - OS', 'DXC - Applications', 'DXC', 'Synology', "Externally Facing - HK VoIP", "DXC - DMZ"):
        new_file, data = [filename], [data]
    else:
        logger.error(f"Category '{filename}' not recognized - SKIP PROCESSING")
        return None, None

    region = None
    region_to_exclude = None
    if 'AMER' in filename:
        region = 'AMER'
        region_to_exclude = 'WHQ'  #'site:00677'
    elif 'APAC' in filename:
        region = 'APAC'
        region_to_exclude = 'CN'
    elif 'EMEA' in filename:
        region = 'EMEA'
    # TODO: Patchwork to keep from needing to rework logic.
    elif 'UC' in filename or 'CGI' in filename or 'DXC' in filename or 'Synology' in filename or 'VoIP' in filename:
        new_file, data = [new_file], [data]
    else:
        logger.error(f"Region '{filename}' not recognized - SKIP PROCESSING")
        return

    if region:
        # TODO: Patchwork to keep from needing to rework logic.
        # data becomes a list of lists (2D vector) (equivalent to vector<vector<DataFrame>>)
        # data[i] is a list of two dataframes (AMER and WHQ)
        # new_file is a list of lists of names (equivalent to vector<vector<string>>)
        for idx, _ in enumerate(data):
            new_file[idx], data[idx] = process_region(data=data[idx], 
                                                      category=new_file[idx],
                                                      region=region, 
                                                      unknown_regions=unknown_regions,
                                                      region_to_exclude=region_to_exclude)
            logger.info(f'process_region - new_file={new_file[idx]}, data={len(data[idx])}')
    
    data = process_and_record_data(new_file, data, count)
    
    process_final_file(new_file, data, processed_data_path, today_date_str, all_workstations)

    return unknown_regions, count

# For all operating system files, they will be split between Workstations and Servers
def process_os(data: pd.DataFrame) -> tuple[list[str], list[pd.DataFrame]]:
    """
    Process OS data and split between workstations and servers.
    """
    logger.info("Filtering applied: OS criteria")

    # Workstation criteria
    workstation_criteria = data['Asset OS Name'].str.contains('Microsoft Windows 1') & \
                           data['Asset OS Version'].str.startswith('2')
    work = data[workstation_criteria]

    # Server criteria - includes blanks
    server_criteria = ~(data['Asset OS Name'].str.contains('Microsoft Windows') |
                        data['Asset OS Name'].str.contains('ROUTER') |
                        data['Asset OS Name'].str.contains('RT') |
                        data['Asset OS Name'].str.contains('NETWORK')) | \
                      data['Asset OS Name'].str.contains('Microsoft Windows Server')
    server = data[server_criteria]

    return ['Workstations', 'Servers'], [work, server]

def process_network(data: pd.DataFrame) -> tuple[list[str], list[pd.DataFrame]]:
    """
    Process network data.
    """
    logger.info("Filtering applied: Network criteria")
    # network = data[~data['Asset OS Name'].str.contains('Windows')]
    # return ['Network'], [network]
    return ['Network'], [data]

def process_app(data: pd.DataFrame) -> tuple[list[str], list[pd.DataFrame]]:
    """
    Process application data, excluding specific vulnerability IDs.
    """
    logger.info("Filtering applied: Applications criteria")

    app = data[~(data['Vulnerability ID'].str.contains('msft-cve') |
                 data['Vulnerability ID'].str.contains('mssql-obsolete') |
                 data['Vulnerability ID'].str.contains('windows-10-obsolete') |
                 data['Vulnerability ID'].str.contains('snmp'))]
    return ['Applications'], [app]

# NOTE: Keeping method for later review.
def process_uc(data: pd.DataFrame) -> tuple[list[str], list[pd.DataFrame]]:
    """
    Process UC data, excluding specific asset names and vulnerability IDs.
    """
    logger.info("Processing UC")

    uc_criteria = ~(data['Asset Names'].str.contains('mersive') | data['Asset Names'].str.contains('Mersive'))
    self_criteria = data['Vulnerability ID'].str.contains('ssl-self-signed-certificate')

    uc = data[uc_criteria & ~self_criteria]
    _self = data[self_criteria & uc_criteria]

    return ['UC', 'Self-signed'], [uc, _self]

def process_region(data: pd.DataFrame, category: str, region: str, unknown_regions: list, 
                   region_to_exclude: str = None) -> tuple[list[str], list[pd.DataFrame]]:
    """
    Filter data based on regions and update unknown regions.

    data (pd.DataFrame): The input dataframe.
    category (str): Category of the report (e.g., 'Workstations', 'Servers').
    region (str): The region to include.
    region_to_exclude (str, optional): The region to exclude. Defaults to None.
    unknown_regions (list, optional): A list to store unknown regions data.
    """
    logger.info(f"Filtering applied: {region} criteria")

    category_mapping = {'Workstations': 0, 'Servers': 0, 'Network': 1, 'Applications': 2}
    valid_category = category in category_mapping

    region_condition = data['Asset Location'].str.contains(region)
    exclude_data = []
    if region_to_exclude:
        logger.info(f"filter data for region: '{region}'...")
        logger.info(f"exclude data for region: '{region_to_exclude}'...")
        exclude_condition = data['Asset Location'].str.contains(region_to_exclude)
        exclude_data = data[exclude_condition]
        region_data = data[region_condition & ~exclude_condition]
    else:
        logger.info(f"filter data for region: '{region}'...")
        region_data = data[region_condition]

    if valid_category:
        logger.info(f"update 'other' data for category: '{category}'...")
        other_data = data[~region_condition]
        target_index = category_mapping[category]

        # Updating unknown regions
        if len(unknown_regions[target_index]) == 1:
            unknown_regions[target_index].append(other_data)
        else:
            unknown_regions[target_index][1] = pd.concat([unknown_regions[target_index][1], other_data])
    
    if region_to_exclude:
        return [f'{region}-{category}', f'{region_to_exclude}-{category}'], [region_data, exclude_data]
    else:
        return [f'{region}-{category}'], [region_data]

def process_and_record_data(new_file: list[str], data: list[pd.DataFrame], count: list) -> list[pd.DataFrame]:
    """
    Deduplicate data and log the results.
    """
    for i in range(len(data)):
        for j in range(len(data[i])):
            dedup = data[i][j].drop_duplicates()
            row_diff = len(data[i][j].index) - len(dedup.index)

            logger.info(
                f"{new_file[i][j]}: Out of {len(data[i][j].index)} total entries, {row_diff} duplicates were detected and removed. {len(dedup.index)} unique values remain."
            )
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
            count.append([new_file[i][j], crit_count, high_count, len(dedup.index)])
            data[i][j] = dedup  # Replace the original DataFrame with the deduplicated DataFrame
            logger.info(f'final data length = {len(data[i][j])}')
    return data

def process_final_file(new_file: list[list[str]], data: list[list[pd.DataFrame]], 
                       processed_data_path: str, today_date_str: str, all_workstations: pd.DataFrame) -> pd.DataFrame:
    """
    Processes final output files, saves them to Excel, and splits large data into multiple sheets if necessary.
    """
    logger.info("Writing contents to file...")
    
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
    excel_filename = filename + today_date_str + '.xlsx'

    logger.info(
        f"Output path: {processed_data_path} \t Filename: {filename} \t Join: {os.path.join(processed_data_path, filename)}")
    # Exporting to Excel file with multiple sheets, and handling large datasets by exporting to CSV if necessary
    try:
        excel_file_path = os.path.join(processed_data_path, excel_filename)
        with pd.ExcelWriter(excel_file_path) as writer:
            for i, file_group in enumerate(new_file):
                logger.info(f'file_group : {file_group}')
                for j, sheet_name in enumerate(file_group):
                    logger.info(f'sheet_name : {sheet_name}')
                    logger.info(data[i][j].head())
                    if len(data[i][j]) > 0:
                        try:
                            if 'Workstations' in sheet_name:  # add dataframe to 'all workstations'

                                if all_workstations.empty:
                                    all_workstations = data[i][j]
                                else:
                                    all_workstations = pd.concat([all_workstations, data[i][j]])

                            data[i][j].to_excel(writer, sheet_name=new_file[i][j], na_rep='', index=False)
                            logger.info(f"...finished processing {sheet_name}. Saved as {excel_filename}")
                        except ValueError as ve:
                            # INFO: Fallback to save as CSV if failed to save data as Excel file
                            # DONE: Consider splitting the file into two excel sheets rather than csv
                            logger.info("Splitting original dataframe into sheets if needed...")

                            sheets_list = CommonFunctions.split_dataframe(data[i][j])
                            excel_file_path = os.path.join(processed_data_path, filename + today_date_str + ".xlsx")
                            CommonFunctions.publish_data_into_excel_file_with_sheets(excel_file_path, sheets_list)
                            # csv_filename = filename.replace(' - ', ' ') + '.csv'
                            # data[i][j].to_csv(os.path.join(processed_data_path, csv_filename), na_rep='', index=False)
                            logger.error(
                                f"{ve}\n...Unable to write to Excel due to row count. Converting to .csv file(s) instead.")
                            logger.info(f"...finished processing {sheet_name}. Saved as {filename}")
                    else:
                        logger.error(f"...EMPTY DF SKIPPED {sheet_name}. Saved as {filename}")
    except Exception as e:
        logger.error(
            f"Failed to create file Filename: {filename} \t Join: {os.path.join(processed_data_path, filename)}")

# Processes the list of files (workstation OS, sever applications, etc.) with the intent of
# stitching them into a single file.
def process_all_workstations_unknownregions(
        all_workstations: pd.DataFrame, 
        unknown_regions: list, 
        count: list, 
        processed_data_path: str, 
        today_date_str: str) -> None:
    """
    Generate files for all workstations and unknown regions, and export them to Excel.

    Args:
        all_workstations (pd.DataFrame): Dataframe containing all workstation data.
        unknown_regions (list): List containing unknown region data.
        count (list): List of count data (critical, high, total) for each file.
        processed_data_path (str): Directory to save the processed files.
        today_date_str (str): Date string to append to filenames.
    """
    logger.info('Generating all_workstations files ...')

    # Export 'all_workstations' to Excel
    if not all_workstations.empty:
        logger.info("Splitting all_workstations dataframe into sheets if needed...")
        sheets_list = CommonFunctions.split_dataframe(all_workstations)
        excel_file_path = os.path.join(processed_data_path, 'All Workstations' + today_date_str + ".xlsx")
        CommonFunctions.publish_data_into_excel_file_with_sheets(excel_file_path, sheets_list)
    
    # Export unknown_regions - separate Excel sheets for each region
    logger.info('Generating Unknown Region files ...')
    for i in range(len(unknown_regions)):
        if len(unknown_regions[i]) > 1:  # Makes sure there are actually entries
            base_filename = f'Unknown regions - {unknown_regions[i][0]}'
            if len(unknown_regions[i][1]) > 0:
                sheets_list = CommonFunctions.split_dataframe(unknown_regions[i][1])
                excel_file_path = os.path.join(processed_data_path, base_filename + today_date_str + ".xlsx")
                CommonFunctions.publish_data_into_excel_file_with_sheets(excel_file_path, sheets_list)
            else:
                logger.info(f'... EMPTY DF SKIPPED, base_filename: {base_filename}')

    # Export count data to Excel
    logger.info('Generating Total Count file ...')
    count_df = pd.DataFrame(count, columns=['File', 'Critical', 'High', 'Total'])
    count_df.sort_values('File', inplace=True)  # Sort to match order of weekly tracker spreadsheet

    logger.info("Splitting count_df dataframe into sheets if needed...")
    sheets_list = CommonFunctions.split_dataframe(count_df)
    excel_file_path = os.path.join(processed_data_path, 'Total Count' + today_date_str + ".xlsx")
    CommonFunctions.publish_data_into_excel_file_with_sheets(excel_file_path, sheets_list)
    
    logger.info('...finished processing Total Count.xlsx')
