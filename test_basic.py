from app.services.analyzer import analyze_url

def test_url(): assert 'score' in analyze_url('https://bit.ly/x')
