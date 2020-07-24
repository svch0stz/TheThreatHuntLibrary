# {{hunt['id']}}-{{hunt['title']}}

***Creation Date:*** {{hunt['creation_date']}}

***Author:*** {{hunt['author']}}

***Target Platform:*** {{hunt['platform']}}

***Analytics:***{% if 'analytics' in hunt %}{% for analytic in hunt['analytics'] %}

- {{analytic['name']}} - {% for source in analytic['data_sources'] %}{{source}}{% if not loop.last %}, {% endif %}{% endfor %}{% endfor %}{% else %}N/A{% endif %}

## Hypothesis

{{hunt['hypothesis']}}

## Description

{{hunt['description']}}

## ATT&CK Detection
{% if 'attack_coverage' in hunt %}
|Technique|Subtechnique(s)|Tactic(s)|
|---|---|---|{% for coverage_item in hunt['attack_coverage'] %}
|[{{techniques[coverage_item['technique']]}}](https://attack.mitre.org/techniques/{{coverage_item['technique']}}/)|{% if 'subtechniques' in coverage_item %}{% for subtechnique in coverage_item['subtechniques'] %}[{{techniques[subtechnique]}}](https://attack.mitre.org/techniques/{{subtechnique | replace(".","/")}}/){% if not loop.last %}, {% endif %}{% endfor %}{% else %}N/A{% endif %}|{% for tactic in coverage_item['tactics'] %}[{{tactics[tactic]}}](https://attack.mitre.org/tactics/{{tactic}}/){% if not loop.last %}, {% endif %}{% endfor %}|{% endfor %}{% endif %}

## Analytics
{% if 'analytics' in hunt %}{% for analytic in hunt['analytics'] %}
### {{analytic['name']}}

***Data Source:*** {% for source in analytic['data_sources'] %}{{source}}{% if not loop.last %}, {% endif %}{% endfor %}

***Description:*** {{analytic['description']}}

***Logic:***
```
{{analytic['logic']}}
```{% endfor %}{% else %}N/A{% endif %}

## Atomic Tests
{% if 'attack_coverage' in hunt %}{% for coverage_item in hunt['attack_coverage'] %}{% if coverage_item['technique'] in tests %}
[{{coverage_item['technique']}} - {{techniques[coverage_item['technique']]}}](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{{coverage_item['technique']}}/{{coverage_item['technique']}}.md/)
{% for test in tests[coverage_item['technique']] %}
{{test['Test #']}}. [{{test['Test Name']}}](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{{coverage_item['technique']}}/{{coverage_item['technique']}}.md/#atomic-test-{{test['Test #']}}---{{test['Test Name'] | replace(" ", "-")|lower}}){% endfor %}{% endif %}{% if 'subtechniques' in coverage_item %}{% for subtechnique in coverage_item['subtechniques'] %}{% if subtechnique in tests %}

[{{subtechnique}} - {{techniques[subtechnique]}}](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{{subtechnique}}/{{subtechnique}}.md/){% for test in tests[subtechnique] %}

{{test['Test #']}}. [{{test['Test Name']}}](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{{subtechnique}}/{{subtechnique}}.md/#atomic-test-{{test['Test #']}}---{{test['Test Name'] | replace(" ", "-")|lower}}){% endfor %}{% endif %}{% endfor %}{% endif %}{% endfor %}{% endif %}

## Hunter Notes

{% if 'hunter_notes' in hunt %}{{hunt['hunter_notes'] }}{% else %}N/A{% endif %}

## Hunt Outputs

{% if 'hunt_output' in hunt %}{{hunt['hunt_output'] }}{% else %}N/A{% endif %}

## References

{% if 'references' in hunt %}{{ hunt['references']}}{% else %}N/A{% endif %}
