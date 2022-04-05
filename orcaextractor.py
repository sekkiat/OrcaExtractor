import json
import sys
import csv
import os
import time
import argparse

def read_json(filelocation):
    description_extractor = []
    details_extractor = []
    recommendation_extractor = []
    asset_name_extractor = []
    severity_extractor = []
    category_extractor = []
    extractor = json.load(open(filelocation))
    for x in extractor:
        try:
            description_extractor.append(x["description"])
        except:
            description_extractor.append("")
        try:
            category_extractor.append(x["category"])
        except:
            category_extractor.append("")
        try:
            details_extractor.append(x["details"])
        except:
            details_extractor.append("")
        try:
            recommendation_extractor.append(x["recommendation"])
        except:
            recommendation_extractor.append("")
        try:
            asset_name_extractor.append(x["asset_name"])
        except:
            asset_name_extractor.append("")
        try:
            severity_extractor.append(str(x["findings"]["cve"][0]["nvd"]["cvss3_severity"]))
        except:
            severity_extractor.append("-")
    remove_redundant(filelocation,description_extractor,details_extractor,asset_name_extractor,category_extractor,recommendation_extractor,severity_extractor)

def write_csv(filename,description_extractor,category_extractor,recommendation_extractor,asset_name_extractor,severity_extractor):
    header = ['category','description and summary', 'recommendation','asset_name','severity']
    rows = [description_extractor,category_extractor,recommendation_extractor,asset_name_extractor,severity_extractor]
    with open(os.path.dirname(filename)+"/extracted.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for x in range(len(description_extractor)):
            writer.writerow([category_extractor[x],description_extractor[x],recommendation_extractor[x],asset_name_extractor[x],severity_extractor[x]])
    print("[+] Completed")

def remove_redundant(filelocation,description,detail,asset_name,category,recommendation,severity):
    wait_to_delete = []
    filtered_description_extractor = []
    filtered_category_extractor = []
    filtered_details_extractor = []
    filtered_recommendation_extractor = []
    filtered_asset_name_extractor = []
    filtered_severity_extractor = []
    try:
        for x in range(len(description)):
            target_description = description[x]
            target_details = detail[x]
            target_asset = asset_name[x]
            target_category = category[x]
            target_recommendation = recommendation[x]
            target_severity = severity[x]
            for y in range(len(description)):
                if y != x:
                    if target_description == description[y] and target_details == detail[y]:
                        target_asset = target_asset + "\n" + asset_name[y]
                        wait_to_delete.append(y)
            wait_to_delete.reverse()
            for xy in wait_to_delete:
                description.pop(xy)
                detail.pop(xy)
                asset_name.pop(xy)
                category.pop(xy)
                recommendation.pop(xy)
                severity.pop(xy)
            filtered_description_extractor.append("Description:\n"+target_description+"\nSummary:\n"+target_details)
            filtered_asset_name_extractor.append(target_asset)
            filtered_category_extractor.append(target_category)
            filtered_recommendation_extractor.append(target_recommendation)
            filtered_severity_extractor.append(target_severity)
            wait_to_delete.clear()
    except:
        write_csv(filelocation,filtered_description_extractor,filtered_category_extractor,filtered_recommendation_extractor,filtered_asset_name_extractor,filtered_severity_extractor)

def os_configuration(file):
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Orca Extractor")
    parser.add_argument('-t', "--type",help="[1] for IAM, Lateral Movement, Vulnerabilities. [2] Configuration Review", required=True)
    parser.add_argument('-f', "--file",help="File Path", required=True)
    args = parser.parse_args()
    type = args.type
    file = args.file
    if type == "1":
        read_json(file)
    elif type == "2":
        os_configuration(file)
        #TODO: can update here thanks bro!


