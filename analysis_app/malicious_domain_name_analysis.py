import dash
import dash_core_components as dcc
import dash_html_components as html
from datetime import datetime as dt
import dash_table
import dash_daq as daq
from dash.dependencies import Input, Output, State
import copy
from elasticsearch import Elasticsearch
import numpy as np
import json
from urllib.request import urlopen

es = Elasticsearch()

app = dash.Dash(__name__)

layout = dict(
    # autosize=True,
    # automargin=True,
    margin=dict(l=0, r=0, b=6, t=30),
    # hovermode="closest",
    plot_bgcolor="#F9F9F9",
    paper_bgcolor="#F9F9F9",
    # width=350,
    # height=170,
    legend=dict(font=dict(size=10), orientation="v"),
    mapbox=dict(style="light",
                # center=dict(lon=-78.05, lat=42.54),
                zoom=2,
                ),
)

app.layout = html.Div(children=[
    dcc.Interval(
        id='interval',
        interval=5 * 1000,  # in milliseconds
        n_intervals=0
    ),
    html.H1(children='Malicious Domain Name Analysis',
            style={
                'textAlign': 'center',
                'color': '#2e86c1'
            }),
    dcc.Tabs(id="", value='historical_analysis', children=[
        dcc.Tab([
            html.Div(
                [
                    html.Div(
                        [
                            html.Div([
                                html.Div([
                                    html.P(
                                        "Domain Name:",
                                        style={'display': 'inline',
                                               'color': '#2e86c1',
                                               'font-size': '18px'},
                                        className="control_label"
                                    ),
                                    dcc.Input(
                                        placeholder='Enter a Domain Name',
                                        type='text',
                                        id='input_text',
                                        className='dcc_control'
                                    ),
                                ]),
                                html.Div(id='input_message',
                                         className="control_label"),
                                html.P("Enter the date range for the analysis:",
                                       style={'color': '#2e86c1',
                                              'font-size': '18px', },
                                       className="control_label"),
                                dcc.DatePickerRange(
                                    id='date_range',
                                    min_date_allowed=dt(2020, 1, 5),
                                    className="dcc_control",
                                    style={'borderWidth': '0px',
                                           'padding': '0px',
                                           'float': 'center',
                                           'margin-left': '10px'},
                                ),
                                html.Div(id='date_message',
                                         className="control_label",
                                         style={'margin-bottom': '10px'}),
                                html.Div([
                                    html.Div([
                                        html.P("Requests per:",
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'},
                                               className="control_label", ),
                                        dcc.RadioItems(
                                            id="requests_freq",
                                            options=[
                                                {"label": "Day ",
                                                 "value": "Day"},
                                                {"label": "Hour ",
                                                 "value": "Hour"},
                                                {"label": "Minute ",
                                                 "value": "Minute"},
                                            ],
                                            labelStyle={"display":
                                                            "inline-block"},
                                            style={'color': '#2e86c1'},
                                            className="dcc_control",
                                        ),
                                    ]),
                                    html.Div(id='radio_button_message',
                                             className="control_label",
                                             style={'margin-bottom': '10px'}),
                                    html.Div([
                                        html.P(
                                            "Hour Range:",
                                            style={'display': 'inline',
                                                   'color': '#2e86c1',
                                                   'font-size': '18px'},
                                            className="control_label"
                                        ),
                                        dcc.Input(
                                            placeholder='',
                                            type='text',
                                            id='start_hour',
                                            className='dcc_control',
                                            size='1'
                                        ),
                                        html.P(
                                            "to",
                                            style={'display': 'inline',
                                                   'color': '#2e86c1',
                                                   'font-size': '18px'},
                                            className="control_label"
                                        ),
                                        dcc.Input(
                                            placeholder='',
                                            type='text',
                                            id='end_hour',
                                            className='dcc_control',
                                            size='1'
                                        ),

                                    ], id='hour_range'),
                                    html.Div(id='hour_range_message',
                                             className="control_label",
                                             style={'margin-bottom': '10px'}),
                                    html.Div([html.P("Submit the Queries:",
                                                     style={'display': 'inline',
                                                            'color':
                                                                '#2e86c1',
                                                            'font-size':
                                                                '18px'},
                                                     className="control_label",
                                                     ),
                                              html.Button('Submit',
                                                          id='submit_input',
                                                          n_clicks=0,
                                                          style={'float':
                                                                     'center',
                                                                 'margin-left':
                                                                     '30px',
                                                                 'color':
                                                                     '#2e86c1'},
                                                          ),
                                              ], ),
                                ]),
                            ], className='pretty_container'),

                            html.Div([
                                dcc.Graph(id='pie_graph')
                            ], className="pretty_container",
                            )
                        ],
                        className="four columns",
                        id="pie",
                    ),
                    html.Div([
                        dcc.Tabs(id='tabs-example', value='tab-1', children=[
                            dcc.Tab([
                                html.Div([dcc.Graph(id='freq_graph', )]), ],
                                label='Requests Plot', value='tab-1',
                                className='pretty_container'),
                            dcc.Tab([
                                html.Div([
                                    html.Br(),
                                    html.P(
                                        "List of IP addresses that queried the Domain",
                                        style={'color': '#333',
                                               'font-size': '18px',
                                               'text-align': 'center'
                                               },
                                        # className="control_label"
                                    ),
                                    html.Br(),
                                    dash_table.DataTable(
                                        id='ip_table_',
                                        columns=[{'id': 'sl_no',
                                                  'name': 'Sl. No.'},
                                                 {'id': 'ip',
                                                  'name': 'IP Address'},
                                                 {'id': 'count',
                                                  'name': 'Queries'}],
                                        fixed_rows={'headers': True},
                                        style_table={
                                            'height': 380,
                                            'overflowY': 'auto',
                                            'backgroundColor': '#F9F9F9',
                                            'margin-left': '10px'
                                        },
                                        style_as_list_view=True,
                                        style_cell={
                                            'padding': '5px',
                                            'backgroundColor': '#F9F9F9',
                                            'whiteSpace': 'no-wrap',
                                            'overflow': 'hidden',
                                            'textOverflow': 'ellipsis',
                                            'textAlign': 'center',
                                            'font-family': 'Arial',
                                            'color': '#333',
                                            'fontSize': 15
                                        },
                                        style_header={
                                            'fontWeight': 'bold'
                                        },
                                    )
                                ], )
                            ], label='IP Address', value='tab-2',
                                className='pretty_container', id='ip_table'),
                            dcc.Tab([
                                daq.ToggleSwitch(
                                    id='mal_toggle_switch',
                                    value=False,
                                    vertical=False,
                                    labelPosition='bottom',
                                    style={'float': 'right'}
                                ),
                                html.Br(),
                                html.Div([
                                    html.Br(),
                                    html.P(
                                        "Malicious Domains",
                                        style={'color': '#333',
                                               'font-size': '18px',
                                               'text-align': 'center'
                                               },
                                        # className="control_label"
                                    ),
                                    html.Br(),
                                    dash_table.DataTable(
                                        id='mal_dns_table',
                                        columns=[{'id': 'sl_no',
                                                  'name': 'Sl. No.'},
                                                 {'id': 'domain',
                                                  'name': 'Domain Names'},
                                                 {'id': 'acc',
                                                  'name': 'Accuracy %'},
                                                 {'id': 'count',
                                                  'name': 'Queries'}],
                                        fixed_rows={'headers': True},
                                        data=[{'sl_no': 1, 'ip': 1, 'count': 1}],
                                        style_table={
                                            'height': 360,
                                            'overflowY': 'auto',
                                            'backgroundColor': '#F9F9F9',
                                            'margin-left': '10px'
                                        },
                                        style_as_list_view=True,
                                        style_cell={
                                            'padding': '5px',
                                            'backgroundColor': '#F9F9F9',
                                            'whiteSpace': 'no-wrap',
                                            'overflow': 'hidden',
                                            'textOverflow': 'ellipsis',
                                            'textAlign': 'center',
                                            'font-family': 'Arial',
                                            'color': '#333',
                                            'fontSize': 15,
                                            'maxWidth': 0
                                        },
                                        style_data_conditional=[
                                            {
                                                'if': {
                                                    'filter_query': '{acc} < 95',
                                                    'column_id': i
                                                },
                                                'backgroundColor': '#f8b0a8',
                                            } for i in ['sl_no', 'domain', 'acc',
                                                        'count']
                                        ],
                                        style_header={
                                            'fontWeight': 'bold'
                                        },
                                    )
                                ], id='mal_dns_table_div'),
                                html.Div([
                                    html.Br(),
                                    dcc.Graph(id='mal_bar_graph', )],
                                    id='mal_bar_graph_div'),
                            ],
                                label='Malicious Domains',
                                value='tab-3', className='pretty_container'),
                            dcc.Tab([
                                daq.ToggleSwitch(
                                    id='benign_toggle_switch',
                                    value=False,
                                    vertical=False,
                                    labelPosition='bottom',
                                    style={'float': 'right'}
                                ),
                                html.Br(),
                                html.Div([
                                    html.Br(),
                                    html.P(
                                        "Benign Domains",
                                        style={'color': '#333',
                                               'font-size': '18px',
                                               'text-align': 'center'
                                               },
                                        # className="control_label"
                                    ),
                                    html.Br(),
                                    dash_table.DataTable(
                                        id='benign_dns_table',
                                        columns=[{'id': 'sl_no',
                                                  'name': 'Sl. No.'},
                                                 {'id': 'domain',
                                                  'name': 'Domain Names'},
                                                 {'id': 'acc',
                                                  'name': 'Accuracy %'},
                                                 {'id': 'count',
                                                  'name': 'Queries'}],
                                        fixed_rows={'headers': True},
                                        style_table={
                                            'height': 360,
                                            'overflowY': 'auto',
                                            'backgroundColor': '#F9F9F9',
                                            'margin-left': '10px'
                                        },
                                        style_as_list_view=True,
                                        style_cell={
                                            'padding': '5px',
                                            'backgroundColor': '#F9F9F9',
                                            'whiteSpace': 'no-wrap',
                                            'overflow': 'hidden',
                                            'textOverflow': 'ellipsis',
                                            'textAlign': 'center',
                                            'font-family': 'Arial',
                                            'color': '#333',
                                            'fontSize': 15,
                                            'maxWidth': 0
                                        },
                                        style_data_conditional=[
                                            {
                                                'if': {
                                                    'filter_query': '{acc} < 95',
                                                    'column_id': i
                                                },
                                                'backgroundColor': '#f8b0a8',
                                            } for i in ['sl_no', 'domain', 'acc',
                                                        'count']
                                        ],
                                        style_header={
                                            'fontWeight': 'bold'
                                        },
                                    )
                                ], id='benign_dns_table_div'),

                                html.Div([
                                    html.Br(),
                                    dcc.Graph(id='benign_bar_graph', )],
                                    id='benign_bar_graph_div'),

                            ],
                                label='Benign Domains',
                                value='tab-4', className='pretty_container'),

                            dcc.Tab([
                                html.Div([
                                    html.Div([

                                        html.Br(),

                                        html.P(['Domain Name: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_domain')

                                    ], style={'margin-bottom': '10px',
                                              'margin-top': '10px'}),

                                    html.Div([
                                        html.P(['IP Addresses: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_ips')

                                    ], style={'margin-bottom': '10px'}),

                                    html.Div([
                                        html.P(['Host Names: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_hostnames')

                                    ], style={'margin-bottom': '10px'}),

                                    html.Div([
                                        html.P(['City: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_city')

                                    ], style={'margin-bottom': '10px'}),

                                    html.Div([
                                        html.P(['State: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_state')

                                    ], style={'margin-bottom': '10px'}),

                                    html.Div([
                                        html.P(['Country: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_country')

                                    ], style={'margin-bottom': '10px'}),

                                    html.Div([
                                        html.P(['Date Registered: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_date')

                                    ], style={'margin-bottom': '10px'}),

                                    html.Div([
                                        html.P(['Registrar: '],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'}, ),
                                        html.P([],
                                               style={'display': 'inline',
                                                      'color': '#2e86c1',
                                                      'font-size': '18px'
                                                      },
                                               id='whois_registrar')

                                    ], style={'margin-bottom': '10px'}),

                                ], style={'margin-left': '40px'})

                            ], label='WhoIS Info', value='tab-5',
                                className='pretty_container')

                        ]),

                    ], className="pretty_container eight columns",
                        style={'color': '#2e86c1', 'font-size': '16px'}),

                ],
                className="row flex-display",
            ),
        ], label='Historical Analysis', value='historical_analysis',
            className='pretty_container'
        ),

        dcc.Tab([
            html.Div([
                html.Div(
                    [
                        dcc.Tabs(id="vet_tab_selected", value='not_vetted',
                                 children=[
                                     dcc.Tab([
                                         html.Div([
                                             html.Br(),
                                             html.P(
                                                 "List of Non - Vetted Domains",
                                                 style={'color': '#333',
                                                        'font-size': '18px',
                                                        'text-align': 'center'
                                                        },
                                                 # className="control_label"
                                             ),
                                             html.Br(),
                                             dash_table.DataTable(
                                                 id='not_vetted_table',
                                                 columns=[{'id': 'sl_no',
                                                           'name': 'Sl. No.'},
                                                          {'id': 'domain',
                                                           'name': 'Domain Name'},
                                                          {'id': 'class',
                                                           'name': 'Classification'},
                                                          {'id': 'acc',
                                                           'name': 'Accuracy %'}],
                                                 fixed_rows={'headers': True},
                                                 style_table={
                                                     'height': 380,
                                                     'overflowY': 'auto',
                                                     'backgroundColor': '#F9F9F9',
                                                     'margin-left': '10px'
                                                 },
                                                 style_as_list_view=True,
                                                 style_cell={
                                                     'padding': '5px',
                                                     'backgroundColor': '#F9F9F9',
                                                     'whiteSpace': 'no-wrap',
                                                     'overflow': 'hidden',
                                                     'textOverflow': 'ellipsis',
                                                     'textAlign': 'center',
                                                     'font-family': 'Arial',
                                                     'color': '#333',
                                                     'fontSize': 15
                                                 },
                                                 style_header={
                                                     'fontWeight': 'bold'
                                                 },
                                                 row_selectable="multi",
                                                 selected_rows=[],
                                             )
                                         ], )
                                     ], label='Not Vetted', value='not_vetted',
                                         className='pretty_container'),
                                     dcc.Tab([
                                         html.Div([
                                             html.Br(),
                                             html.P(
                                                 "List of Benign Domains",
                                                 style={'color': '#333',
                                                        'font-size': '18px',
                                                        'text-align': 'center'
                                                        },
                                                 # className="control_label"
                                             ),
                                             html.Br(),
                                             dash_table.DataTable(
                                                 id='benign_vet_table',
                                                 columns=[{'id': 'sl_no',
                                                           'name': 'Sl. No.'},
                                                          {'id': 'domain',
                                                           'name': 'Domain Name'},
                                                          {'id': 'class',
                                                           'name': 'Classification'},
                                                          {'id': 'acc',
                                                           'name': 'Accuracy %'}],
                                                 fixed_rows={'headers': True},
                                                 style_table={
                                                     'height': 380,
                                                     'overflowY': 'auto',
                                                     'backgroundColor': '#F9F9F9',
                                                     'margin-left': '10px'
                                                 },
                                                 style_as_list_view=True,
                                                 style_cell={
                                                     'padding': '5px',
                                                     'backgroundColor': '#F9F9F9',
                                                     'whiteSpace': 'no-wrap',
                                                     'overflow': 'hidden',
                                                     'textOverflow': 'ellipsis',
                                                     'textAlign': 'center',
                                                     'font-family': 'Arial',
                                                     'color': '#333',
                                                     'fontSize': 15
                                                 },
                                                 style_header={
                                                     'fontWeight': 'bold'
                                                 },
                                                 row_selectable="multi",
                                                 selected_rows=[],
                                             )
                                         ], )
                                     ], label='Benign', value='benign_vet',
                                         className='pretty_container'),
                                     dcc.Tab([
                                         html.Div([
                                             html.Br(),
                                             html.P(
                                                 "List of Honeypotted Domains",
                                                 style={'color': '#333',
                                                        'font-size': '18px',
                                                        'text-align': 'center'
                                                        },
                                                 # className="control_label"
                                             ),
                                             html.Br(),
                                             dash_table.DataTable(
                                                 id='honeypot_vet_table',
                                                 columns=[{'id': 'sl_no',
                                                           'name': 'Sl. No.'},
                                                          {'id': 'domain',
                                                           'name': 'Domain Name'},
                                                          {'id': 'class',
                                                           'name': 'Classification'},
                                                          {'id': 'acc',
                                                           'name': 'Accuracy %'}],
                                                 fixed_rows={'headers': True},
                                                 style_table={
                                                     'height': 380,
                                                     'overflowY': 'auto',
                                                     'backgroundColor': '#F9F9F9',
                                                     'margin-left': '10px'
                                                 },
                                                 style_as_list_view=True,
                                                 style_cell={
                                                     'padding': '5px',
                                                     'backgroundColor': '#F9F9F9',
                                                     'whiteSpace': 'no-wrap',
                                                     'overflow': 'hidden',
                                                     'textOverflow': 'ellipsis',
                                                     'textAlign': 'center',
                                                     'font-family': 'Arial',
                                                     'color': '#333',
                                                     'fontSize': 15
                                                 },
                                                 style_header={
                                                     'fontWeight': 'bold'
                                                 },
                                                 row_selectable="multi",
                                                 selected_rows=[],
                                             )
                                         ], )
                                     ], label='Honeypot', value='honeypot',
                                         className='pretty_container'),
                                     dcc.Tab([
                                         html.Div([
                                             html.Br(),
                                             html.P(
                                                 "List of Blacklisted Domains",
                                                 style={'color': '#333',
                                                        'font-size': '18px',
                                                        'text-align': 'center'
                                                        },
                                                 # className="control_label"
                                             ),
                                             html.Br(),
                                             dash_table.DataTable(
                                                 id='blacklist_vet_table',
                                                 columns=[{'id': 'sl_no',
                                                           'name': 'Sl. No.'},
                                                          {'id': 'domain',
                                                           'name': 'Domain Name'},
                                                          {'id': 'class',
                                                           'name': 'Classification'},
                                                          {'id': 'acc',
                                                           'name': 'Accuracy %'}, ],
                                                 fixed_rows={'headers': True},
                                                 style_table={
                                                     'height': 380,
                                                     'overflowY': 'auto',
                                                     'backgroundColor': '#F9F9F9',
                                                     'margin-left': '10px'
                                                 },
                                                 style_as_list_view=True,
                                                 style_cell={
                                                     'padding': '5px',
                                                     'backgroundColor': '#F9F9F9',
                                                     'whiteSpace': 'no-wrap',
                                                     'overflow': 'hidden',
                                                     'textOverflow': 'ellipsis',
                                                     'textAlign': 'center',
                                                     'font-family': 'Arial',
                                                     'color': '#333',
                                                     'fontSize': 15
                                                 },
                                                 style_header={
                                                     'fontWeight': 'bold'
                                                 },
                                                 row_selectable="multi",
                                                 selected_rows=[],
                                             )
                                         ], )
                                     ], label='Blacklist', value='blacklist',
                                         className='pretty_container'),
                                 ], style={'color': '#2e86c1', 'font-size': '18px'}),
                    ], className='pretty_container nine columns',
                ),
                html.Div([
                    html.Div([
                        html.P("Change Status:",
                               style={'display': 'inline',
                                      'color': '#2e86c1',
                                      'font-size': '18px'},
                               className="control_label", ),
                        dcc.RadioItems(
                            id="change_status",
                            options=[
                                {"label": "Not Vetted", "value": "not_vetted"},
                                {"label": "Benign", "value": "benign_vet"},
                                {"label": "Honeypot", "value": "honeypot"},
                                {"label": "Blacklist", "value": "blacklist"}
                            ],
                            labelStyle={"display": "inline-block"},
                            style={'color': '#2e86c1'},
                            className="dcc_control",
                        ),
                        html.Div([html.Div(id='input_vet_message',
                                           className="control_label"),
                                  html.Br(),
                                  html.Button('Submit',
                                              id='submit_vet_input',
                                              n_clicks=0,
                                              style={'float': 'right',
                                                     'margin-right': '-6px',
                                                     'color': '#2e86c1',
                                                     'font': 'Arial'}, ),
                                  ], )
                    ]),

                ], className='pretty_container three columns')
            ], className="row")

        ], label='Manual Vetting', value='manual_vetting',
            className='pretty_container',
        )
    ], style={'color': '#2e86c1', 'font-size': '18px', 'width': '500px'})
])


# Non Decorated Functions

# Historical Analysis

# Control Messages

def input_message(n_clicks, value):
    try:
        keys = es.indices.get('*').keys()
    except:
        keys = []
    if value is None or value == '':
        return 'Please enter a Domain Name'
    elif value in keys:
        return 'You have entered: ' + value
    else:
        return 'Domain Name does not exist in Database'


def date_message(n_clicks, freq, start_date, end_date):
    if start_date is None or end_date is None:
        return 'Please enter the date range'
    elif freq == 'Hour' or freq == 'Minute':
        start = int(start_date.split('-')[2])
        end = int(end_date.split('-')[2])
        if (end - start) == 1:
            return 'Data from {} to {}'.format(start_date, end_date)
        else:
            return 'For hours or minutes please enter two consecutive days'
    elif freq == 'Day':
        start = int(start_date.split('-')[1])
        end = int(end_date.split('-')[1])
        if (end - start) == 0:
            return 'Data from {} to {}'.format(start_date, end_date)
        else:
            return 'For days please enter a range within the same month'
    else:
        return 'Data from {} to {}'.format(start_date, end_date)


def radio_button_message(n_clicks, value):
    if value is None:
        return 'Please select an option'
    else:
        return 'You have selected: ' + value


def hour_range_message(freq, start, end):
    if freq is None or freq == 'Day':
        return html.Div([])
    elif start is None or start is '' or end is None or end is '':
        return 'Enter an integer hour range (0 to 24)'
    else:
        try:
            start_ = int(start)
            end_ = int(end)
            diff = end_ - start_
            if 0 <= start_ <= 24 and 0 <= end_ <= 24 and diff > 0:
                if freq == 'Minute':
                    if diff > 1:
                        return 'The difference between the ranges should be 1'
                    else:
                        return 'Hour range from {} to {}'.format(start_, end_)
                else:
                    return 'Hour range from {} to {}'.format(start_, end_)
            else:
                return 'Please enter relevant integer values (0 to 24) '
        except:
            return 'Please enter integer values (0 to 24)'


# Graph and Div Updates


def display_hour_range(value):
    if value is None or value == 'Day':
        return {'display': 'none'}
    else:
        return {'display': 'unset'}


def update_pie_graph(n_clicks, value):
    layout_pie = copy.deepcopy(layout)
    layout_pie["title"] = 'Prediction'
    layout_pie["font"] = dict(color="#777777")
    layout_pie["legend"] = dict(font=dict(color="#777777", size="10"),
                                orientation="v", bgcolor="rgba(0,0,0,0)")
    layout_pie["width"] = '350'
    layout_pie["height"] = '150'
    if value is None or value is '':
        data = [
            dict(
                type="pie",
                labels=["Benign", "Malicious"],
                values=[0.5, 0.5],
                textinfo="label+percent+name",
                hole=0.5,
                marker=dict(colors=["#3498db", "#f5b041 "]),
                domain={"x": [0.2, 0.9], "y": [0.2, 0.9]},
            )]
        figure = dict(data=data, layout=layout_pie)
        return figure
    else:
        try:
            pred = float(es.get(index=value, id=1)['_source']['status'])
        except:
            pred = 0.5
        data = [
            dict(
                type="pie",
                labels=["Benign", "Malicious"],
                values=[1 - pred, pred],
                textinfo="label+percent+name",
                hole=0.5,
                marker=dict(colors=["#3498db", "#f5b041 "]),
                domain={"x": [0.2, 0.9], "y": [0.2, 0.9]},
            )]
        figure = dict(data=data, layout=layout_pie)
        return figure


def update_line_graph(n_clicks, start_hour, end_hour, input_value,
                      start_date, end_date, freq_value):
    layout_count = copy.deepcopy(layout)
    layout_count['title'] = "Requests"
    if freq_value is None:
        freq_value = ''
    layout_count['xaxis'] = {'title': 'Time in ' + freq_value + 's'}
    layout_count['yaxis'] = {'title': 'Number of Requests'}
    layout_count['autosize'] = True
    layout_count['margin'] = dict(l=0, r=0, b=20, t=30),
    if input_value is None or input_value == '' or start_date is None or \
            end_date is None or freq_value is None:
        layout_count['title'] = "Requests (Please fill the entries)"
        layout_count['xaxis'] = {'title': ''}
        data = [
            dict(
                type="line",
                # mode="markers",
                x=[],
                y=[],
                # opacity=0,
                hoverinfo="skip",
            )]
        figure = dict(data=data, layout=layout_count)
        return figure
    else:
        if freq_value == 'Minute':
            try:
                req = es.get(index=input_value, id=1)['_source'][start_date][start_hour]
                x = [i for i in req.keys()]
                y = [i for i in req.values()]
            except:
                layout_count['title'] = "Requests (Data not found)"
                layout_count['xaxis'] = {'title': ''}
                x = []
                y = []
            data = [
                dict(
                    type="line",
                    x=x,
                    y=y,
                )]
            figure = dict(data=data, layout=layout_count)
            return figure
        elif freq_value == 'Hour':
            try:
                req = es.get(index=input_value, id=1)['_source'][start_date]
                hours = [str(i) for i in range(int(start_hour), int(end_hour))]
                x = list(set(hours) & set(req.keys()))
                y = [np.sum(list(req[i].values())) for i in x]
            except:
                layout_count['title'] = "Requests (Data not found)"
                layout_count['xaxis'] = {'title': ''}
                x = []
                y = []
            data = [
                dict(
                    type="line",
                    x=x,
                    y=y,
                )]
            figure = dict(data=data, layout=layout_count)
            return figure
        elif freq_value == 'Day':
            start = start_date.split('-')
            start[1], start[2] = start[1].lstrip('0'), start[2].lstrip('0')
            end = end_date.split('-')
            end[1], end[2] = end[1].lstrip('0'), end[2].lstrip('0')

            try:
                req = es.get(index=input_value, id=1)['_source']
                req = req[start[0]][start[1]]
                print(req)
                if (int(end[1]) - int(start[1])) == 0:
                    days = [str(i) for i in range(int(start[2]),
                                                  (int(end[2]) + 1))]

                    x = list(set(days) & set(req.keys()))
                    y = [req[i] for i in x]
                else:
                    x = [i for i in req.keys()]
                    y = [req[i] for i in x]
            except:
                layout_count['title'] = "Requests (Data not found)"
                layout_count['xaxis'] = {'title': ''}
                x = []
                y = []
            data = [
                dict(
                    type="line",
                    x=x,
                    y=y,
                )]
            figure = dict(data=data, layout=layout_count)
            return figure


def update_ip_table(nclicks, value):
    if value is None or value == '':
        return []
    else:
        try:
            count = es.get(index=value, id=1)['_source']['count']
            domain_names = [key for (key, value) in sorted(count.items(),
                                                           key=lambda x: x[1],
                                                           reverse=True)]
            data = [dict({'sl_no': j + 1, 'ip': i, 'count': count[i]})
                    for i, j in zip(domain_names, range(len(count)))]
        except:
            data = []
        return data


def display_mal_list(value):
    if value is False:
        return {'display': 'none'}
    else:
        return {'display': 'unset'}


def display_mal_graph(value):
    if value is False:
        return {'display': 'unset'}
    else:
        return {'display': 'none'}


def update_mal_dns_table(nclicks, value):
    try:
        mal = es.get(index='mal', id=1)['_source']
        domain_names = [key for (key, value) in
                        sorted(mal.items(), key=lambda x: x[1]['count'],
                               reverse=True)]
        data = [dict({'sl_no': j + 1, 'domain': i,
                      'acc': mal[i]['status'], 'count': mal[i]['count']})
                for i, j in zip(domain_names, range(len(mal)))]
    except:
        data = []
    return data


def update_mal_bar_graph(value, interval):
    try:
        mal = es.get(index='mal', id=1)['_source']
    except:
        mal = {}
    if len(mal) < 20:
        domain_names = [key for (key, value) in
                        sorted(mal.items(), key=lambda x: x[1]['count'],
                               reverse=True)]
    else:
        domain_names = [key for (key, value) in
                        sorted(mal.items(), key=lambda x: x[1]['count'],
                               reverse=True)][0:20]

    layout_bar = copy.deepcopy(layout)
    layout_bar['title'] = "Top Malicious Domains Queried"
    layout_bar['xaxis'] = {'title': 'Rank (Hover over the bars for more info)',
                           'tickvals': [(i + 1) for i in
                                        range(len(domain_names))]}
    layout_bar['yaxis'] = {'title': 'Number of Requests'}
    layout_bar['margin'] = dict(l=30, r=30, b=20, t=30),
    layout_bar['height'] = '400'
    data = [
        dict(
            type="bar",
            hovertext=domain_names,
            x=[(i + 1) for i in range(len(domain_names))],
            y=[int(mal[i]['count']) for i in domain_names],
        )]
    figure = dict(data=data, layout=layout_bar)
    return figure


def display_benign_list(value):
    if value is False:
        return {'display': 'none'}
    else:
        return {'display': 'unset'}


def display_benign_graph(value):
    if value is True:
        return {'display': 'none'}
    else:
        return {'display': 'unset'}


def update_benign_dns_table(nclicks, value):
    try:
        benign = es.get(index='benign', id=1)['_source']
        domain_names = [key for (key, value) in
                        sorted(benign.items(), key=lambda x: x[1]['count'],
                               reverse=True)]
        data = [dict({'sl_no': j + 1, 'domain': i,
                      'acc': benign[i]['status'], 'count': benign[i]['count']})
                for i, j in zip(domain_names, range(len(benign)))]
    except:
        data = []
    return data


def update_benign_bar_graph(value, interval):
    try:
        benign = es.get(index='benign', id=1)['_source']
    except:
        benign = {}
    if len(benign) < 20:
        domain_names = [key for (key, value) in
                        sorted(benign.items(), key=lambda x: x[1]['count'],
                               reverse=True)]
    else:
        domain_names = [key for (key, value) in
                        sorted(benign.items(), key=lambda x: x[1]['count'],
                               reverse=True)][0:20]

    layout_bar = copy.deepcopy(layout)
    layout_bar['title'] = "Top Benign Domains Queried"
    layout_bar['xaxis'] = {'title': 'Rank (Hover over the bars for more info)',
                           'tickvals': [(i + 1) for i in
                                        range(len(domain_names))]}
    layout_bar['yaxis'] = {'title': 'Number of Requests'}
    layout_bar['margin'] = dict(l=30, r=30, b=20, t=30),
    layout_bar['height'] = '400'
    data = [
        dict(
            type="bar",
            hovertext=domain_names,
            x=[(i + 1) for i in range(len(domain_names))],
            y=[int(benign[i]['count']) for i in domain_names],
        )]
    figure = dict(data=data, layout=layout_bar)
    return figure


def update_whois_info(n_clicks, domain_name):
    whois_ip = ''
    whois_hostnames = ''
    whois_city = ''
    whois_state = ''
    whois_country = ''
    whois_date_registered = ''
    whois_registrar = ''

    if domain_name is None or domain_name == '':
        domain_name = ''

    else:

        try:
            api_key = 'at_r4GfBsGDWwZpuaga703KB9HZBmG6S'
            url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService?' \
                  + 'domainName=' + domain_name + '&apiKey=' + api_key + \
                  "&outputFormat=JSON" + "&ip=1"

            data = json.loads(urlopen(url).read().decode('utf8'))

            if 'ErrorMessage' in data.keys():

                domain_name = data['msg']

            else:

                try:
                    ips = data['WhoisRecord']['ips']
                    for i in ips:
                        whois_ip = whois_ip + i + ' '
                except:
                    whois_ip = '-'

                try:
                    hostnames = data['WhoisRecord']['nameServers']['hostNames']
                    for i in hostnames:
                        whois_hostnames = whois_hostnames + i + ' '
                except:
                    whois_hostnames = '-'

                try:
                    whois_city = data['WhoisRecord']['registrant']['city']
                except:
                    whois_city = '-'

                try:
                    whois_state = data['WhoisRecord']['registrant']['state']
                except:
                    whois_state = '-'

                try:
                    whois_country = data['WhoisRecord']['registrant']['country']
                except:
                    whois_country = '-'

                try:
                    whois_date_registered = \
                        data['WhoisRecord']['registryData']['createdDateNormalized']
                except:
                    whois_date_registered = '-'

                try:
                    whois_registrar = data['WhoisRecord']['registrarName']
                except:
                    whois_registrar = '-'

        except:
            domain_name = domain_name + ' (WhoIS Unresponsive)'

    return domain_name, whois_ip, whois_hostnames, whois_city, \
           whois_state, whois_country, whois_date_registered, whois_registrar


# Manual Vetting


def update_and_input_vet_message_vet_tables(n_clicks, not_vetted_select,
                                            benign_vet_select,
                                            honeypot_vet_select,
                                            blacklist_vet_select,
                                            change_status):
    vet_list = [not_vetted_select, benign_vet_select, honeypot_vet_select,
                blacklist_vet_select]
    es_vet_list_names = ['not_vetted', 'benign_vet', 'honeypot', 'blacklist']
    if change_status is None:
        for i in vet_list:
            if i is not None and i != []:
                return 'Please select the option, the entries have to be ' \
                       'changed to.', None, None, None, None, None
        return 'Please select the entries on the left whose status has to be ' \
               'changed and also select the option, the entries have to be ' \
               'changed to.', None, None, None, None, None
    else:
        for i, j in zip(vet_list, es_vet_list_names):
            if i is not None and i != []:
                if change_status in j:
                    return 'Please enter a different option to change the ' \
                           'status.', None, None, None, None, None
                else:
                    body_to_change = es.get(index=j, id=1)['_source']
                    body_to_change_keys = \
                        list(es.get(index=j, id=1)['_source'].keys())

                    for k in i:
                        body_to_update = \
                            {'doc':
                                 {body_to_change_keys[k]:
                                      body_to_change[body_to_change_keys[k]]}}
                        es.update(index=change_status, id=1, body=body_to_update)

                    for k in i:
                        del (body_to_change[body_to_change_keys[k]])
                    es.index(j, id=1, body=body_to_change)
                    return 'Status change successful.', \
                           None, None, None, None, None

        return 'Please select the entries on the left whose status has to be ' \
               'changed.', None, None, None, None, None


def update_not_vetted_table(n_intervals):
    try:
        not_vetted = es.get(index='not_vetted', id=1)['_source']
        data = [dict({'sl_no': j + 1, 'domain': i,
                      'class': not_vetted[i]['class'],
                      'acc': not_vetted[i]['acc']})
                for i, j in zip(not_vetted.keys(), range(len(not_vetted)))]
    except:
        data = []
    return data


def update_benign_vet_table(n_intervals):
    try:
        benign_vet = es.get(index='benign_vet', id=1)['_source']
        data = [dict({'sl_no': j + 1, 'domain': i,
                      'class': benign_vet[i]['class'],
                      'acc': benign_vet[i]['acc']})
                for i, j in zip(benign_vet.keys(), range(len(benign_vet)))]
    except:
        data = []
    return data


def update_honeypot_vet_table(n_intervals):
    try:
        honeypot_vet = es.get(index='honeypot', id=1)['_source']
        data = [dict({'sl_no': j + 1, 'domain': i,
                      'class': honeypot_vet[i]['class'],
                      'acc': honeypot_vet[i]['acc']})
                for i, j in zip(honeypot_vet.keys(), range(len(honeypot_vet)))]
    except:
        data = []
    return data


def update_blacklist_vet_table(n_intervals):
    try:
        blacklist_vet = es.get(index='blacklist', id=1)['_source']
        data = [dict({'sl_no': j + 1, 'domain': i,
                      'class': blacklist_vet[i]['class'],
                      'acc': blacklist_vet[i]['acc']})
                for i, j in zip(blacklist_vet.keys(),
                                range(len(blacklist_vet)))]
    except:
        data = []
    return data


# Dash Functions

# Historical Analysis

# Control Messages


@app.callback(Output('input_message', 'children'),
              [Input('submit_input', 'n_clicks')],
              [State('input_text', 'value')])
def input_message_dash(n_clicks, value):
    return_input_message = input_message(n_clicks, value)
    return return_input_message


@app.callback(Output('date_message', 'children'),
              [Input('submit_input', 'n_clicks'),
               Input('requests_freq', 'value'),
               Input('date_range', 'start_date'),
               Input('date_range', 'end_date')])
def date_message_dash(n_clicks, freq, start_date, end_date):
    date_message_ = date_message(n_clicks, freq, start_date, end_date)
    return date_message_


@app.callback(Output('radio_button_message', 'children'),
              [Input('submit_input', 'n_clicks'),
               Input('requests_freq', 'value')])
def radio_button_message_dash(n_clicks, value):
    radio_button_message_ = radio_button_message(n_clicks, value)
    return radio_button_message_


@app.callback(Output('hour_range_message', 'children'),
              [Input('requests_freq', 'value'),
               Input('start_hour', 'value'),
               Input('end_hour', 'value')])
def hour_range_message_dash(freq, start, end):
    hour_range_message_ = hour_range_message(freq, start, end)
    return hour_range_message_


# Graphs and Div Updates


@app.callback(Output('hour_range', 'style'),
              [Input('requests_freq', 'value')])
def display_hour_range_dash(value):
    display = display_hour_range(value)
    return display


@app.callback(Output('pie_graph', 'figure'),
              [Input('submit_input', 'n_clicks')],
              [State('input_text', 'value')])
def update_pie_graph_dash(n_clicks, value):
    figure = update_pie_graph(n_clicks, value)
    return figure


@app.callback(Output('freq_graph', 'figure'),
              [Input('submit_input', 'n_clicks'), ],
              [State('start_hour', 'value'),
               State('end_hour', 'value'),
               State('input_text', 'value'),
               State('date_range', 'start_date'),
               State('date_range', 'end_date'),
               State('requests_freq', 'value')])
def update_line_graph_dash(n_clicks, start_hour, end_hour, input_value,
                           start_date, end_date, freq_value):
    figure = update_line_graph(n_clicks, start_hour, end_hour, input_value,
                               start_date, end_date, freq_value)
    return figure


@app.callback(Output('ip_table_', 'data'),
              [Input('submit_input', 'n_clicks')],
              [State('input_text', 'value')])
def update_ip_table_dash(nclicks, value):
    data = update_ip_table(nclicks, value)
    return data


@app.callback(Output('mal_dns_table_div', 'style'),
              [Input('mal_toggle_switch', 'value')])
def display_mal_list_dash(value):
    display = display_mal_list(value)
    return display


@app.callback(Output('mal_bar_graph_div', 'style'),
              [Input('mal_toggle_switch', 'value')])
def display_mal_graph_dash(value):
    display = display_mal_graph(value)
    return display


@app.callback(Output('mal_dns_table', 'data'),
              [Input('mal_toggle_switch', 'value'),
               Input('interval', 'n_intervals')])
def update_mal_dns_table_dash(nclicks, value):
    data = update_mal_dns_table(nclicks, value)
    return data


@app.callback(Output('mal_bar_graph', 'figure'),
              [Input('mal_toggle_switch', 'value'),
               Input('interval', 'n_intervals')])
def update_mal_bar_graph_dash(value, interval):
    figure = update_mal_bar_graph(value, interval)
    return figure


@app.callback(Output('benign_dns_table_div', 'style'),
              [Input('benign_toggle_switch', 'value')])
def display_benign_list_dash(value):
    display = display_benign_list(value)
    return display


@app.callback(Output('benign_bar_graph_div', 'style'),
              [Input('benign_toggle_switch', 'value')])
def display_benign_graph_dash(value):
    display = display_benign_graph(value)
    return display


@app.callback(Output('benign_dns_table', 'data'),
              [Input('mal_toggle_switch', 'value'),
               Input('interval', 'n_intervals')])
def update_benign_dns_table_dash(nclicks, value):
    data = update_benign_dns_table(nclicks, value)
    return data


@app.callback(Output('benign_bar_graph', 'figure'),
              [Input('benign_toggle_switch', 'value'),
               Input('interval', 'n_intervals')])
def update_benign_bar_graph_dash(value, interval):
    figure = update_benign_bar_graph(value, interval)
    return figure


@app.callback([Output('whois_domain', 'children'),
               Output('whois_ips', 'children'),
               Output('whois_hostnames', 'children'),
               Output('whois_city', 'children'),
               Output('whois_state', 'children'),
               Output('whois_country', 'children'),
               Output('whois_date', 'children'),
               Output('whois_registrar', 'children')],
              [Input('submit_input', 'n_clicks')],
              [State('input_text', 'value')])
def update_whois_info_dash(n_clicks, domain_name):
    whois_domain, whois_ips, whois_hostnames, whois_city, whois_state, \
    whois_country, whois_date, whois_registrar = \
        update_whois_info(n_clicks, domain_name)

    return whois_domain, whois_ips, whois_hostnames, whois_city, whois_state, \
           whois_country, whois_date, whois_registrar


# Manual Vetting

@app.callback([Output('input_vet_message', 'children'),
               Output('change_status', 'value'),
               Output('not_vetted_table', "derived_viewport_selected_rows"),
               Output('benign_vet_table', "derived_viewport_selected_rows"),
               Output('honeypot_vet_table', "derived_viewport_selected_rows"),
               Output('blacklist_vet_table', "derived_viewport_selected_rows")],
              [Input('submit_vet_input', 'n_clicks')],
              [State('not_vetted_table', "derived_viewport_selected_rows"),
               State('benign_vet_table', "derived_viewport_selected_rows"),
               State('honeypot_vet_table', "derived_viewport_selected_rows"),
               State('blacklist_vet_table', "derived_viewport_selected_rows"),
               State('change_status', 'value'), ])
def update_and_input_vet_message_vet_tables_dash(n_clicks, not_vetted_select,
                                                 benign_vet_select,
                                                 honeypot_vet_select,
                                                 blacklist_vet_select,
                                                 change_status):
    message, _, _, _, _, _ = update_and_input_vet_message_vet_tables(n_clicks,
                                                                     not_vetted_select,
                                                                     benign_vet_select,
                                                                     honeypot_vet_select,
                                                                     blacklist_vet_select,
                                                                     change_status)
    return message, None, None, None, None, None


@app.callback(Output('not_vetted_table', 'data'),
              [Input('interval', 'n_intervals')])
def update_not_vetted_table_dash(n_intervals):
    data = update_not_vetted_table(n_intervals)
    return data


@app.callback(Output('benign_vet_table', 'data'),
              [Input('interval', 'n_intervals')])
def update_benign_vet_table_dash(n_intervals):
    data = update_benign_vet_table(n_intervals)
    return data


@app.callback(Output('honeypot_vet_table', 'data'),
              [Input('interval', 'n_intervals')])
def update_honeypot_vet_table_dash(n_intervals):
    data = update_honeypot_vet_table(n_intervals)
    return data


@app.callback(Output('blacklist_vet_table', 'data'),
              [Input('interval', 'n_intervals')])
def update_blacklist_vet_table_dash(n_intervals):
    data = update_blacklist_vet_table(n_intervals)
    return data


if __name__ == '__main__':
    app.run_server(debug=True)
