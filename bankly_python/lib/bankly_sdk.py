import requests
import json
from json import JSONDecodeError
from datetime import datetime, timedelta
from fastapi import HTTPException
import uuid
from requests.models import HTTPError
from common.get_creds import get_creds
from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter


CREDS = get_creds()

def load_certificate_data():
    mtls_certificate = '/tmp/.certficate'
    mtls_key = '/tmp/.certificate_key'
    with open(mtls_certificate,  'w') as f:
        f.write(json.loads(CREDS['mtls_certificate_data'])['certificate'])
        f.close()

    with open(mtls_key, 'w') as f:
        f.write(json.loads(CREDS['mtls_certificate_data'])['privateKey'])
        f.close()

    return [mtls_certificate, mtls_key]

API_ENDPOINT = CREDS['bankly_api_url']
LOGIN_ENDPOINT = CREDS['bankly_api_login_endpoint']
DEFAULT_API_VERSION=CREDS['bankly_api_version']
COMPANY_KEY = CREDS['company_key']
MTLS_CERTIFICATES_ENDPOINT = CREDS['bankly_mtls_api_certificate_endpoint']
MTLS_CLIENT_REGISTER_ENDPOINT = CREDS['bankly_mtls_api_client_register_endpoint']
MTLS_LOGIN_ENDPOINT = CREDS['bankly_mtls_api_login_endpoint']
SUCCESS_HTTP_CODES = [200,201,202,204]

MTLS_CERTIFICATE_DATA = load_certificate_data()


SESSION_TYPES_AND_SCOPES = {
    'PIX' : ['pix.account.read', 'pix.entries.create', 'pix.entries.delete', 'pix.entries.read', 'pix.qrcode.create', 'pix.qrcode.read', 'pix.cashout.create', 'pix.cashout.read'],
    'KYC' : ['kyc.document.write', 'kyc.document.read'],
    'CUSTOMER' : ['customer.write', 'customer.read', 'customer.cancel'],
    'BUSINESS' : ['business.write', 'business.read', 'business.cancel'],
    'CARD' : ['card.create', 'card.update', 'card.read', 'card.pci.password.update', 'card.pci.read'],
    'ACCOUNT' : ['account.create', 'account.read', 'account.close'],
    'BANKSLIP' : ['boleto.create', 'boleto.read', 'boleto.delete'],
    'PAYMENT' : ['payment.validate', 'payment.confirm', 'payment.read'],
    'TRANSFER' : ['ted.cashout.create', 'ted.cashout.read'],
    'EVENTS' : ['events.read'],
    'COMMON' : ['zipcode.read', 'banklist.read'],
}

class SSLAdapter(HTTPAdapter):    
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.load_cert_chain(certfile=MTLS_CERTIFICATE_DATA[0], keyfile=MTLS_CERTIFICATE_DATA[1], password=json.loads(CREDS['mtls_certificate_data'])['passphrase'])
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)


class BanklySession:
    def __init__(self, type, scope_list):
        self.session_is_active = False
        self.session_token = None
        self.session_time_limit = None
        self.mtls_client = None
        self.type = type
        self.scope_list = scope_list
        self.mtls = True

    '''
        Auth and Session Operations
    '''

    def authenticate(self):
        if self.session_is_active == True:
            if not self.session_time_limit < datetime.now():
                return
        if self.mtls:
            session = requests.Session()
            session.mount("https://", SSLAdapter())
            if not self.mtls_client:
                headers = {
                    "Accept": "application/json",
                }
                payload = {
                    "grant_types" : ["client_credentials"],
                    "tls_client_auth_subject_dn" : json.loads(CREDS['mtls_certificate_data'])['subjectDn'],
                    "token_endpoint_auth_method" : "tls_client_auth",
                    "response_types" : ["access_token"],
                    "company_key" : COMPANY_KEY,
                    "scope" : ' '.join(self.scope_list)
                }
                try:     
                    response = session.post(MTLS_CLIENT_REGISTER_ENDPOINT, json=payload)
                    self.mtls_client = response.json()
                except Exception as e:
                    print(e)
                    raise
            payload = f"grant_type=client_credentials&client_id={self.mtls_client['client_id']}"
            scopes_str = ' '.join(self.scope_list)
            payload += f"&scope={scopes_str}"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            try:
                response = session.post(MTLS_LOGIN_ENDPOINT, data=payload, headers=headers)
            except Exception as e:
                print(e)   
                raise

        else:
            payload = f"grant_type=client_credentials&client_id={CREDS['bakly_client_id']}&client_secret={CREDS['bankly_client_secret']}"
            scopes_str = ' '.join(self.scope_list)
            payload += f"&scope={scopes_str}"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            try:
                response = requests.request("POST", LOGIN_ENDPOINT, data=payload, headers=headers)
            except Exception as e:
                print(e)
                raise

        self.session_is_active = True
        self.session_token = response.json()['access_token']
        self.session_time_limit = datetime.now() + timedelta(seconds=response.json()['expires_in']-30)

    def _check_session(self):
        if not self.session_is_active or self.session_time_limit < datetime.now():
            self.authenticate()
        if not self.session_is_active:
            raise Exception('Cannot get api session, failing.')


class BanklyClient:

    def __init__(self):
        self.sessions = {}
        for session_type in SESSION_TYPES_AND_SCOPES.keys():
            new_session = BanklySession(session_type, SESSION_TYPES_AND_SCOPES[session_type])
            self.sessions[session_type] = new_session
    

    '''
        Common Operations
    '''        
    def get_bank_list(self, params):
        session_type = 'COMMON'
        op_url = API_ENDPOINT + '/banklist'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type, params=params)

    def get_bank_by_id(self, id):
        session_type = 'COMMON'
        op_url = API_ENDPOINT + f'/banklist/{id}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)        

    def get_address_by_zipcode(self, zipCode):
        session_type = 'COMMON'
        op_url = API_ENDPOINT + f'/addresses/{zipCode}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)        


    '''
        Customer Operations
    '''

    def put_customer_document_analysis(self, customer_document, data_payload, files_payload):
        session_type = 'KYC'
        op_url = API_ENDPOINT + f'/document-analysis/{customer_document}'
        self.sessions[session_type]._check_session()
        return self._put_operation(op_url, data_payload=data_payload, files_payload=files_payload, session_type=session_type)

    def get_customer_document_analysis(self, customer_document, params):
        session_type = 'KYC'
        op_url = API_ENDPOINT + f'/document-analysis/{customer_document}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)

    def put_customer(self, customer_document, data_payload):
        session_type = 'CUSTOMER'
        op_url = API_ENDPOINT + f'/customers/{customer_document}'
        self.sessions[session_type]._check_session()
        return self._put_operation(op_url, data_payload=data_payload, session_type=session_type)

    def get_customer(self, customer_document, params={'resultLevel':'DETAILED'}):
        session_type = 'CUSTOMER'
        op_url = API_ENDPOINT + f'/customers/{customer_document}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)

    def post_customer_accounts(self, customer_document, data_payload):
        session_type = 'ACCOUNT'
        op_url = API_ENDPOINT + f'/customers/{customer_document}/accounts'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def get_customer_accounts(self, customer_document):
        session_type = 'ACCOUNT'
        op_url = API_ENDPOINT + f'/customers/{customer_document}/accounts'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def get_account_detail(self, account_number, params={"includeBalance":"true"}):
        session_type = 'ACCOUNT'
        op_url = API_ENDPOINT + f'/accounts/{account_number}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)

    '''
        Business Operations
    '''
    def put_business(self, business_document, data_payload):
        session_type = 'BUSINESS'
        op_url = API_ENDPOINT + f'/business/{business_document}'
        self.sessions[session_type]._check_session()
        return self._put_operation(op_url, data_payload=data_payload, session_type=session_type)

    def get_business(self, business_document, params={'resultLevel':'DETAILED'}):
        session_type = 'BUSINESS'
        op_url = API_ENDPOINT + f'/business/{business_document}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)

    def get_business_accounts(self, business_document):
        session_type = 'ACCOUNT'
        op_url = API_ENDPOINT + f'/business/{business_document}/accounts'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def post_business_accounts(self, business_document, data_payload):
        session_type = 'ACCOUNT'
        op_url = API_ENDPOINT + f'/business/{business_document}/accounts'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    '''
        Cards Operations
    '''
    def post_virtual_card(self, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/virtual'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def post_physical_card(self, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/physical'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def post_multiple_card(self, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/multiple'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def post_duplicate_card(self, proxy, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/duplicate'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def get_card_by_proxy(self, proxy):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def get_card_by_document_number(self, document_number):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/document/{document_number}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def get_card_by_activate_code(self, activation_code):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/activateCode/{activation_code}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def get_card_by_account_number(self, account_number, params):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/account/{account_number}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)
    
    def post_card_pci_by_proxy(self, proxy, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/pci'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def patch_card_password_by_proxy(self, proxy, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/password'
        self.sessions[session_type]._check_session()
        return self._patch_operation(op_url, data_payload=data_payload, session_type=session_type)

    def post_card_wallet_token_by_proxy(self, proxy, wallet, brand):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards-pci/{proxy}/wallet/{wallet}/brand/{brand}'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, session_type=session_type)

    def path_card_activation_by_proxy(self, proxy, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/activate'
        self.sessions[session_type]._check_session()
        return self._patch_operation(op_url, data_payload=data_payload, session_type=session_type)

    def path_card_status_by_proxy(self, proxy, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/status'
        self.sessions[session_type]._check_session()
        return self._patch_operation(op_url, data_payload=data_payload, session_type=session_type)

    def path_card_contactless_by_proxy(self, proxy, data_payload):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/contactless?allowContactless={data_payload}'
        self.sessions[session_type]._check_session()
        return self._patch_operation(op_url, session_type=session_type)

    def get_card_allowed_next_status_by_proxy(self, proxy):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/nextStatus'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def get_card_transations_by_proxy(self, proxy, params):
        session_type = 'CARD'
        op_url = API_ENDPOINT + f'/cards/{proxy}/transactions'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)    

    '''
        Bankslip Operations
    '''

    def post_bankslip(self, data_payload):
        session_type = 'BANKSLIP'
        op_url = API_ENDPOINT + f'/bankslip'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type) 

    def get_bankslip(self, branch, number, authenticationCode):
        session_type = 'BANKSLIP'
        op_url = API_ENDPOINT + f'/bankslip/branch/{branch}/number/{number}/{authenticationCode}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def get_bankslip_pdf(self, authenticationCode):
        session_type = 'BANKSLIP'
        op_url = API_ENDPOINT + f'/bankslip/{authenticationCode}/pdf'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, is_file=True, session_type=session_type)

    def get_bankslip_by_date(self, date):
        session_type = 'BANKSLIP'
        op_url = API_ENDPOINT + f'/bankslip/searchstatus/{date}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def delete_bankslip(self, data_payload):
        session_type = 'BANKSLIP'
        op_url = API_ENDPOINT + f'/bankslip/cancel'
        self.sessions[session_type]._check_session()
        return self._delete_operation(op_url, data_payload=data_payload, session_type=session_type)

    def post_bankslip_settlementpayment(self, data_payload):
        session_type = 'BANKSLIP'
        op_url = API_ENDPOINT + f'/bankslip/settlementpayment'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)    

    '''
        Fund Transfers Operations
    '''

    def post_fund_transfer(self, data_payload):
        session_type = 'TRANSFER'
        op_url = API_ENDPOINT + f'/fund-transfers'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, add_guid = True, session_type=session_type)           

    def get_fund_transfer_by_authentication_code(self, authenticationCode, params):
        session_type = 'TRANSFER'
        op_url = API_ENDPOINT + f'/fund-transfers/{authenticationCode}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, guid=str(uuid.uuid4()), session_type=session_type)             

    def get_fund_transfers_by_account(self, params):
        session_type = 'TRANSFER'
        op_url = API_ENDPOINT + f'/fund-transfers'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, guid=str(uuid.uuid4()), session_type=session_type)     

    '''
        Bill Payment Operations
    '''

    def post_validate_bill_payment(self, data_payload):
        session_type = 'PAYMENT'
        op_url = API_ENDPOINT + f'/bill-payment/validate'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, add_guid = True, session_type=session_type)
    
    def post_confirm_bill_payment(self, data_payload):
        session_type = 'PAYMENT'
        op_url = API_ENDPOINT + f'/bill-payment/confirm'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, add_guid = True, session_type=session_type)
    
    def get_bill_payments_by_account(self, params):
        session_type = 'PAYMENT'
        op_url = API_ENDPOINT + f'/bill-payment'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)

    def get_bill_payments_detail(self, params):
        session_type = 'PAYMENT'
        op_url = API_ENDPOINT + f'/bill-payment/detail'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, session_type=session_type)

    '''
        PIX Operations
    '''

    def get_pix_keys(self, accountNumber):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/accounts/{accountNumber}/addressing-keys'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def post_pix_key(self, data_payload):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/pix/entries'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)       

    def delete_pix_key(self, addressingKeyValue):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/pix/entries/{addressingKeyValue}'
        self.sessions[session_type]._check_session()
        return self._delete_operation(op_url, session_type=session_type)

    def get_pix_key(self, addressingKeyValue, documentNumber):
        session_type = 'PIX' 
        op_url = API_ENDPOINT + f'/pix/entries/{addressingKeyValue}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, pix_document = documentNumber, session_type=session_type)

    def post_pix_cash_out(self, data_payload):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/pix/cash-out'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)     

    def get_pix_cash_out(self, accountNumber, authenticationCode):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/pix/cash-out/accounts/{accountNumber}/authenticationcode/{authenticationCode}'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, session_type=session_type)

    def post_pix_cash_out_refund(self, data_payload):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/pix/cash-out:refund'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def post_pix_static_qrcode(self, data_payload):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/pix/qrcodes'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    def post_pix_decode_qrcode(self, data_payload):
        session_type = 'PIX'
        op_url = API_ENDPOINT + f'/pix/qrcodes/decode'
        self.sessions[session_type]._check_session()
        return self._post_operation(op_url, data_payload=data_payload, session_type=session_type)

    '''
        Events Operations
    '''

    def get_event(self, params):
        session_type = 'EVENTS'
        op_url = API_ENDPOINT + f'/events'
        self.sessions[session_type]._check_session()
        return self._get_operation(op_url, params=params, guid=str(uuid.uuid4()), session_type=session_type)
        

    '''
        Base Operations
    '''

    def _get_operation(self, url, session_type, params=None, is_file = False, guid = None, pix_document = None):
        headers = {
            "Authorization": "Bearer " + self.sessions[session_type].session_token,
            "Accept": "application/json",
            "api-version": DEFAULT_API_VERSION
        }
        if guid:
            headers['x-correlation-id'] = guid

        if pix_document:
            headers['x-bkly-pix-user-id'] = pix_document

        session = requests.Session()
        session.mount("https://", SSLAdapter())
        response = session.get(url, headers=headers, params=params) 

        if response.status_code in SUCCESS_HTTP_CODES:
            if is_file:
                return response.content
            else:
                try:
                    return response.json()
                except JSONDecodeError:
                    return response.text
        else:
            print(f'ERROR - {response.status_code} - {response.text}')
            try:
                raise HTTPException(status_code=response.status_code, detail=response.json())
            except:
                try:
                    raise HTTPException(status_code=response.status_code, detail=dict(response.json()))
                except JSONDecodeError:
                    raise HTTPException(status_code=response.status_code)

    def _put_operation(self, url, session_type, data_payload=None, files_payload=None):
        headers = {
            "Authorization": "Bearer " + self.sessions[session_type].session_token,
            "Accept": "application/json",
            "api-version": DEFAULT_API_VERSION,
        }

        session = requests.Session()
        session.mount("https://", SSLAdapter())
        response = session.put(url, headers=headers, data=data_payload, files=files_payload)

        if response.status_code in SUCCESS_HTTP_CODES:
            if response.text:
                return response.json()
            else:
                return
        else:
            print(f'ERROR - {response.status_code} - {response.text}')
            try:
                raise HTTPException(status_code=response.status_code, detail=response.json())        
            except:
                raise HTTPException(status_code=response.status_code, detail=response.text) 

    def _post_operation(self, url, session_type, data_payload=None, add_guid = None):
        headers = {
            "Authorization": "Bearer " + self.sessions[session_type].session_token,
            "Accept": "application/json",
            "api-version": DEFAULT_API_VERSION,
        }

        if add_guid:
            guid = str(uuid.uuid4())
            print(f'GUID REQUEST: {guid}')
            headers['x-correlation-id'] = guid

        session = requests.Session()
        session.mount("https://", SSLAdapter())
        response = session.post(url, headers=headers, json=data_payload)

        if response.status_code in SUCCESS_HTTP_CODES:
            if response.text:
                return response.json()
            else:
                return
        else:
            print(f'ERROR - {response.status_code} - {response.text}')
            try:
                raise HTTPException(status_code=response.status_code, detail=response.json())        
            except:
                raise HTTPException(status_code=response.status_code, detail=response.text)   


    def _patch_operation(self, url, session_type, data_payload=None):
        headers = {
            "Authorization": "Bearer " + self.sessions[session_type].session_token,
            "Accept": "application/json",
            "api-version": DEFAULT_API_VERSION,
        }
            
        session = requests.Session()
        session.mount("https://", SSLAdapter())
        response = session.patch(url, headers=headers, json=data_payload)

        if response.status_code in SUCCESS_HTTP_CODES:
            if response.text:
                return response.json()
            else:
                return
        else:
            print(f'ERROR - {response.status_code} - {response.text}')
            try:
                raise HTTPException(status_code=response.status_code, detail=response.json())        
            except:
                raise HTTPException(status_code=response.status_code, detail=response.text) 

    def _delete_operation(self, url, session_type, data_payload=None):
        headers = {
            "Authorization": "Bearer " + self.sessions[session_type].session_token,
            "Accept": "application/json",
            "api-version": DEFAULT_API_VERSION,
        }

        session = requests.Session()
        session.mount("https://", SSLAdapter())
        response = session.delete(url, headers=headers, json=data_payload)

        if response.status_code in SUCCESS_HTTP_CODES:
            if response.text:
                return response.json()
            else:
                return
        else:
            print(f'ERROR - {response.status_code} - {response.text}')
            try:
                raise HTTPException(status_code=response.status_code, detail=response.json())        
            except:
                raise HTTPException(status_code=response.status_code, detail=response.text) 