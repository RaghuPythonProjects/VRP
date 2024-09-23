from typing import List, Optional
import os
from datetime import datetime, timedelta
from utilities.sharepoint_api import SharePointAPI
from utilities.logger_master import logger


def get_history_folder_path(history_folder_path, history_folder_name):
    logger.info(
        f'history_folder_path = {history_folder_path}, history_folder_name = {history_folder_name}')
    if history_folder_path and history_folder_name:

        now = datetime.now()
        current_monday = now - timedelta(days=now.weekday())
        target_date = current_monday.strftime("%Y-%m-%d")
        target_year = current_monday.year
        return f"{history_folder_path}/{target_year}/{target_date}/{history_folder_name}"
    else:
        return None

def get_latest_folder_path(latest_folder_path, latest_folder_name):
    logger.info(f'latest_folder_path = {latest_folder_path}, latest_folder_name = {latest_folder_name}')
    if latest_folder_path and latest_folder_name:
        return f"{latest_folder_path}/{latest_folder_name}"
    else:
        return None

def get_report_paths_from_folder(folder):
    path_to_folder = os.path.join(os.getcwd(), folder)
    report_paths = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder)]
    logger.info(f"found {len(report_paths)} files in folder {folder}")

    return report_paths

def get_reports_to_push_to_sharepoint(merge_data_folder, merge_files_dict, merge_data_path, processed_data_path):
    logger.info('get report paths to push to sharepoint')
    if merge_data_folder and merge_files_dict:
        report_paths = get_report_paths_from_folder(merge_data_path)
    else:
        report_paths = get_report_paths_from_folder(processed_data_path)
    return report_paths

def upload_to_sharepoint(latest_folder_path: Optional[str], 
                         latest_folder_name: Optional[str], 
                         history_folder_path: Optional[str], 
                         history_folder_name: Optional[str], 
                         processed_data_path: str, 
                         merge_data_folder: str,
                         merge_data_path: Optional[str], 
                         merge_files_dict: Optional[dict]) -> None:

    latest_folder = get_latest_folder_path(latest_folder_path, latest_folder_name)
    history_folder = get_history_folder_path(history_folder_path, history_folder_name)
    if not latest_folder and not history_folder:
        logger.debug("======= SKIPPING PUSH TO SHAREPOINT - no mention of latest or history folder paths")
        return None
    report_paths = get_reports_to_push_to_sharepoint(merge_data_folder, merge_files_dict, merge_data_path, processed_data_path)
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
