import pytest

@pytest.fixture
def attack_json():
    return {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298",
            "created": "2020-01-14T17:18:32.126Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1055/011",
                    "external_id": "T1055.011"
                },
                {
                    "source_name": "Microsoft Window Classes",
                    "description": "Microsoft. (n.d.). About Window Classes. Retrieved December 16, 2017.",
                    "url": "https://msdn.microsoft.com/library/windows/desktop/ms633574.aspx"
                },
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "modified": "2025-10-24T17:48:19.059Z",
            "name": "Extra Window Memory Injection",
            "description": "Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process. \n\nBefore creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data).(Citation: Microsoft Window Classes) Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value. (Citation: Microsoft GetWindowLong function) (Citation: Microsoft SetWindowLong function)\n\nAlthough small, the EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process\u2019s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process\u2019s EWM.\n\nExecution granted through EWM injection may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as <code>WriteProcessMemory</code> and <code>CreateRemoteThread</code>.(Citation: Elastic Process Injection July 2017) More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process.  (Citation: MalwareTech Power Loader Aug 2013) (Citation: WeLiveSecurity Gapz and Redyms Mar 2013)\n\nRunning code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via EWM injection may also evade detection from security products since the execution is masked under a legitimate process. ",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "defense-evasion"
                },
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "privilege-escalation"
                }
            ],
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_deprecated": False,
            "x_mitre_detection": "",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_is_subtechnique": True,
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_platforms": [
                "Windows"
            ],
            "x_mitre_version": "1.1"
        }

@pytest.fixture
def tactic_json():
    return {
            "type": "x-mitre-tactic",
            "spec_version": "2.1",
            "id": "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0006",
                    "external_id": "TA0006"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "modified": "2025-04-25T14:45:32.408Z",
            "name": "Credential Access",
            "description": "The adversary is trying to steal account names and passwords.\n\nCredential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_deprecated": False,
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_version": "1.0",
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_shortname": "credential-access"
        }

@pytest.fixture
def matrix_json():
    return {
            "type": "x-mitre-matrix",
            "spec_version": "2.1",
            "id": "x-mitre-matrix--eafc1b4c-5e56-4965-bd4e-66a6a89c88cc",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/matrices/enterprise",
                    "external_id": "enterprise-attack"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "modified": "2025-04-25T14:41:40.982Z",
            "name": "Enterprise ATT&CK",
            "description": "Below are the tactics and technique representing the MITRE ATT&CK Matrix for Enterprise. The Matrix contains information for the following platforms: Windows, macOS, Linux, AWS, GCP, Azure, Azure AD, Office 365, SaaS.",
            "tactic_refs": [
                "x-mitre-tactic--daa4cbb1-b4f4-4723-a824-7f1efd6e0592",
                "x-mitre-tactic--d679bca2-e57d-4935-8650-8031c87a4400",
                "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
                "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
                "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
                "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd",
                "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
                "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
                "x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9",
                "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e",
                "x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe",
                "x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813",
                "x-mitre-tactic--9a4e74ab-5008-408c-84bf-a10dfbc53462",
                "x-mitre-tactic--5569339b-94c2-49ee-afb3-2222936582c8"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_deprecated": False,
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_version": "1.0",
            "x_mitre_attack_spec_version": "3.2.0"
        }