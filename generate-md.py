"""
Heavily based of scripts and resourses from:
MITRE Cyber Analytics Repository by MITRE - https://github.com/mitre-attack/car/
ThreatHunter-Playbook by Cyb3rWard0g - https://github.com/hunters-forge/ThreatHunter-Playbook/
Atomic Red Team by Red Canary - https://github.com/redcanaryco/atomic-red-team

Generates Markdown pages from yaml files in hunts/*

The following files are updated by this script, and should not be altered manually:
* docs/index.md
* docs/hunts/*
* docs/data/hunts.json

"""
import pandas as pd
import json
import glob
import yaml
import requests
from jinja2 import Environment, Template, FileSystemLoader
from os import path, makedirs
import copy
import csv
import io

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/subtechniques/enterprise-attack/enterprise-attack.json"
ATOMIC_INDEX_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-CSV/index.csv"

# Get all hunt and load as list of dicts
hunt_path = path.join(path.dirname(__file__), 'hunts', '*.yaml')
hunt_files = glob.glob(hunt_path)
hunts = [yaml.load(open(hunt_file,encoding="utf-8").read(),Loader=yaml.FullLoader) for hunt_file in hunt_files]

# Load ATT&CK content, which is needed to get names for technique IDs
attack = requests.get(ATTACK_URL).json()
techniques = {ap['external_references'][0]['external_id']: ap['name'] for ap in attack['objects'] if ap['type'] == 'attack-pattern'}
tactics = {ap['external_references'][0]['external_id']: ap['name'] for ap in attack['objects'] if ap['type'] == 'x-mitre-tactic'}

# Load Atomic Test Index and group index by Technique
r = requests.get(ATOMIC_INDEX_URL).content
df = pd.read_csv(io.StringIO(r.decode('utf-8')))

#drop tactics column, remove duplicate tests and group by technique id
tests = df.drop('Tactic',1)     \
        .drop_duplicates()     \
        .set_index(['Technique #'])     \
        .groupby('Technique #')     \
        .apply(lambda g: g.to_dict(orient='records'))     \
        .to_json(orient='index')

# Get the template file for the analytic page. Note that this is a markdown template which will be rendered by GH Pages.
template_path = path.join(path.dirname(__file__), 'templates').replace("/","\\") # Changed for Windows Paths
env = Environment(loader=FileSystemLoader(template_path))
hunt_template = env.from_string(open(template_path+'\hunt_template.md').read())
tests = json.loads(tests)
# Generate the page for each hunt
for hunt in hunts:
    hunt_for_render = copy.deepcopy(hunt)
    # Generate the markdown
    markdown = hunt_template.render(hunt=hunt_for_render, tactics=tactics, techniques=techniques, tests=tests)
    # Write to md file
    with open('docs/hunts/{}-{}.md'.format(hunt['id'],hunt['title']), 'w+') as f:
        f.write(markdown)
        f.close()
    print("Generated hunt file - {}-{}.md".format(hunt['id'],hunt['title']))

# Generate the index.md file
index_content = """
# The Threat Hunt Library

## Hunt List

|Hunt|ATT&CK Techniques|Platform(s)|Creation Date|
|---|---|---|---|
"""

subtechnique_table = """---
## Hunt List (by technique/sub-technique coverage)

|ATT&CK Technique|ATT&CK Sub-technique(s)|Hunt|
|---|---|---|
"""

# Build the first (date-based) table
table_techniques = []
for hunt in sorted(hunts, key = lambda k: k['id']):
    coverage = ""
    implementations = ""
    if 'attack_coverage' in hunt and len(hunt['attack_coverage']) > 0:
        coverage += "<ul style='margin-bottom: 0;'>"
        for cov in hunt['attack_coverage']:
          coverage += "<li><a href=\"https://attack.mitre.org/beta/techniques/{}/\">{}</a></li>".format(cov['technique'], cov['technique'] + "-" + techniques[cov['technique']]) 
          # Get all of the techniques seen in all hunts
          # This is for building the second (subtechniques based) table
          if cov['technique'] not in table_techniques:
              table_techniques.append(cov['technique'])
        coverage += "</ul>" 
    if 'platform' in hunt:
        applicable_platforms = hunt['platform']
    else:
        applicable_platforms = "N/A"
    index_content += "|<a href=\"hunts/{}-{}.md\">{}-{}</a>|{}|{}|{}|\n".format(hunt['id'], hunt['title'], hunt['id'],hunt['title'], coverage, applicable_platforms, hunt['creation_date'])

# Build the second (subtechnique-based) table
#print(table_techniques)
for tid in table_techniques:
    # Find all analytics with this technique
    none_bucket = []
    sub_bucket = {}
    for hunt in hunts:
        if "attack_coverage" in hunt:
            for cov in hunt['attack_coverage']:
                if cov["technique"] == tid:
                    if "subtechniques" not in cov:
                        none_bucket.append(hunt)
                    else:
                        for sub_tid in cov["subtechniques"]:
                            if sub_tid not in sub_bucket:
                                sub_bucket[sub_tid] = [hunt]
                            else:
                                sub_bucket[sub_tid].append(hunt)
                    break
    # Write the base technique to the table
    none_str = ""
    none_sub_str = "(N/A - see below)"
    if none_bucket:
        none_str += "<ul style='margin-bottom: 0;'>"
        for hunt in sorted(none_bucket, key = lambda k: k['id']):
            none_str += "<li><a href=\"hunts/{}-{}.md\">{}-{}</a></li>".format(hunt['id'],hunt['title'], hunt['id'], hunt['title'])
        none_str += "</ul>"
        none_sub_str = "(N/A - technique only)"
    else:
        none_str = "(N/A - see below)"
    if len(sub_bucket.keys()) > 1:
      subtechnique_table += "|[{}-{}](https://attack.mitre.org/beta/techniques/{}/)|{}|{}|\n".format(tid,techniques[tid],tid,none_sub_str,none_str)
    # Write the subtechniques to the table
    if sub_bucket:
        for sub_tid, car_list in sub_bucket.items():
            sub_str = "<ul style='margin-bottom: 0;'>"
            for hunt in sorted(car_list, key = lambda k: k['id']):
                sub_str += "<li><a href=\"hunts/{}-{}.md\">{}-{}</a></li>".format(hunt['id'],hunt['title'], hunt['id'], hunt['title'])
            sub_str += "</ul>"
            # Write the sub-technique entry to the table
            # Corner case where there is only one sub-technique and no technique-only analytics
            if not none_bucket and len(sub_bucket.keys()) == 1:
              subtechnique_table += "|[{}-{}](https://attack.mitre.org/beta/techniques/{}/)|[{}-{}](https://attack.mitre.org/beta/techniques/{}/{}/)|{}|\n".format(tid,techniques[tid],tid,sub_tid,techniques[sub_tid],sub_tid.split(".")[0],sub_tid.split(".")[1],sub_str)
            else:
              subtechnique_table += "|...|[{}-{}](https://attack.mitre.org/beta/techniques/{}/{}/)|{}|\n".format(sub_tid,techniques[sub_tid],sub_tid.split(".")[0],sub_tid.split(".")[1],sub_str)

# Write the tables
index_file = open('docs/index.md', 'w')
index_file.write(index_content)
index_file.write("\n")
index_file.write(subtechnique_table)
index_file.close()

# Generate analytics.json
huntdata = [
    {
        'shortName': hunt['title'],
        'name': hunt['id'],
        'attack': [{'tactics': [tactics[t] for t in coverage['tactics']], 'technique': 'Technique/{}'.format(coverage['technique'])} for coverage in hunt['attack_coverage']] if 'attack_coverage' in hunt else []
    } for hunt in hunts
]
makedirs('docs/data/', exist_ok=True)
open('docs/data/hunts.json', 'w').write(json.dumps({'hunts': huntdata}))
