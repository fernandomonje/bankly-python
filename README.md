# bankly-python
## Python integration for Bankly Bank As a Service platform

I have written this code some year a go to implement for a client.
I'm not activelly maintaining this code anymore, my last update on this code was on 2022, some integrations with Bankly API can be deprecated/changed, but this can be useful for someone who is looking for references for integrating with Bankly API.
It was fully developed to be used on AWS environment using Secrets Manager to load certificates.
There is some dependences on FastAPI and Requests libs, it was fully based on my implementation, and I have removed most of the app code that contains other stuff that is not related to Bankly Integration.

Here are the features that this code contains:

- Session Management based on the API Scope
- MTLS
- API Functionalities
    - PIX
    - KYC
    - CUSTOMER
    - BUSINESS
    - CARD
    - ACCOUNT
    - BANKSLIP
    - PAYMENT
    - TRANSFER
    - EVENTS
    - COMMON

As you can see the documentation is poor, it was only me working on this code and the project timing didn't let me dedicate on creating better documentation and tests.

So, that's it, hope that this can be useful as reference.


