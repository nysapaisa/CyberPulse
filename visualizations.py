import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

COLORS = {
    'CRITICAL': '#e05c5c',
    'HIGH':     '#e0875c',
    'MEDIUM':   '#5c9ee0',
    'LOW':      '#5ce0a0',
    'UNKNOWN':  '#6e7681'
}

CHART_COLORS = [
    '#5c9ee0', '#7b5ce0', '#5ce0c8',
    '#e05c9e', '#5ce068', '#e0c45c'
]

def apply_dark_theme(fig, title=''):
    fig.update_layout(
        title=dict(
            text=title,
            font=dict(color='#e6edf3', size=14, family='Inter')
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter', color='#8b949e', size=11),
        legend=dict(
            bgcolor='rgba(0,0,0,0)',
            bordercolor='rgba(0,0,0,0)',
            font=dict(color='#8b949e', size=11)
        ),
        margin=dict(l=10, r=10, t=45, b=10),
        xaxis=dict(
            gridcolor='rgba(139,148,158,0.1)',
            linecolor='rgba(139,148,158,0.2)',
            tickfont=dict(color='#8b949e', size=10),
            showgrid=True
        ),
        yaxis=dict(
            gridcolor='rgba(139,148,158,0.1)',
            linecolor='rgba(139,148,158,0.2)',
            tickfont=dict(color='#8b949e', size=10),
            showgrid=True
        )
    )
    return fig

def severity_donut(df):
    counts = df['Severity'].value_counts().reset_index()
    counts.columns = ['Severity', 'Count']
    fig = px.pie(
        counts, values='Count', names='Severity',
        hole=0.65, color='Severity',
        color_discrete_map=COLORS
    )
    fig.update_traces(
        textposition='outside',
        textinfo='percent+label',
        textfont=dict(color='#8b949e', size=11),
        marker=dict(line=dict(color='#0d1117', width=3)),
        pull=[0.03]*len(counts)
    )
    fig.add_annotation(
        text=f"<b style='font-size:18px'>{len(df)}</b><br><span style='font-size:11px'>Total CVEs</span>",
        x=0.5, y=0.5, showarrow=False,
        font=dict(size=13, color='#e6edf3')
    )
    fig = apply_dark_theme(fig, 'Severity Distribution')
    fig.update_layout(showlegend=True)
    return fig

def daily_trend(df):
    df_copy = df.copy()
    df_copy['Published'] = pd.to_datetime(df_copy['Published']).dt.date
    daily = df_copy.groupby('Published').size().reset_index(name='Count')
    daily['Published'] = pd.to_datetime(daily['Published'])
    daily = daily.sort_values('Published')

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=daily['Published'],
        y=daily['Count'],
        mode='lines+markers',
        line=dict(color='#5c9ee0', width=2),
        marker=dict(
            color='#5c9ee0',
            size=5,
            line=dict(color='#0d1117', width=1)
        ),
        fill='tozeroy',
        fillcolor='rgba(92,158,224,0.07)',
        name='CVEs'
    ))
    fig = apply_dark_theme(fig, 'Daily CVE Publications')
    fig.update_layout(
        showlegend=False,
        xaxis=dict(
            tickformat="%d %b",
            gridcolor='rgba(139,148,158,0.1)',
            linecolor='rgba(139,148,158,0.2)',
            tickfont=dict(color='#8b949e', size=10)
        )
    )
    return fig

def category_bar(df):
    counts = df['Category'].value_counts().reset_index()
    counts.columns = ['Category', 'Count']
    counts = counts.sort_values('Count', ascending=True)

    colors = CHART_COLORS * (len(counts) // len(CHART_COLORS) + 1)
    colors = colors[:len(counts)]

    fig = go.Figure(go.Bar(
        x=counts['Count'],
        y=counts['Category'],
        orientation='h',
        marker=dict(
            color=colors,
            opacity=0.85,
            line=dict(color='rgba(0,0,0,0)')
        ),
        text=counts['Count'],
        textposition='outside',
        textfont=dict(color='#8b949e', size=10)
    ))
    fig = apply_dark_theme(fig, 'Threat Categories')
    fig.update_layout(
        showlegend=False,
        xaxis=dict(
            gridcolor='rgba(139,148,158,0.1)',
            linecolor='rgba(139,148,158,0.2)',
            tickfont=dict(color='#8b949e', size=10)
        ),
        yaxis=dict(
            gridcolor='rgba(0,0,0,0)',
            linecolor='rgba(139,148,158,0.2)',
            tickfont=dict(color='#8b949e', size=10)
        )
    )
    return fig

def score_histogram(df):
    fig = go.Figure(go.Histogram(
        x=df.dropna(subset=['Score'])['Score'],
        nbinsx=20,
        marker=dict(
            color="#06417c",
            opacity=0.8,
            line=dict(color='#0d1117', width=1)
        )
    ))
    fig.add_vline(
        x=7.0,
        line_dash='dash',
        line_color='rgba(224,135,92,0.7)',
        line_width=1.5,
        annotation_text='High',
        annotation_font_color='#e0875c',
        annotation_font_size=11
    )
    fig.add_vline(
        x=9.0,
        line_dash='dash',
        line_color='rgba(224,92,92,0.7)',
        line_width=1.5,
        annotation_text='Critical',
        annotation_font_color='#e05c5c',
        annotation_font_size=11
    )
    fig = apply_dark_theme(fig, 'CVSS Score Distribution')
    fig.update_layout(showlegend=False)
    return fig

def severity_over_time(df):
    df_copy = df.copy()
    df_copy['Published'] = pd.to_datetime(
        df_copy['Published']
    ).dt.to_period('W').dt.start_time
    grouped = df_copy.groupby(
        ['Published', 'Severity']
    ).size().reset_index(name='Count')
    grouped = grouped.sort_values('Published')

    fig = px.bar(
        grouped, x='Published', y='Count',
        color='Severity',
        color_discrete_map=COLORS,
        barmode='stack'
    )
    fig = apply_dark_theme(fig, 'Severity Breakdown Over Time (Weekly)')
    fig.update_layout(
        bargap=0.25,
        xaxis=dict(
            tickformat="%b %Y",
            gridcolor='rgba(139,148,158,0.1)',
            linecolor='rgba(139,148,158,0.2)',
            tickfont=dict(color='#8b949e', size=10)
        )
    )
    return fig