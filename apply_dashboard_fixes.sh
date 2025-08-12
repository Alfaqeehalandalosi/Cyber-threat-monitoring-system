#!/bin/bash

# Apply dashboard fixes for cache functionality

echo "Applying dashboard fixes..."

# 1. Update make_api_request function to support force_refresh
sed -i 's/def make_api_request(endpoint: str, timeout: int = 30) -> Dict\[str, Any\]:/def make_api_request(endpoint: str, timeout: int = 30, force_refresh: bool = False) -> Dict\[str, Any\]:/' dashboard.py

# 2. Add force_refresh parameter logic to make_api_request
sed -i '/url = f"{API_BASE_URL}{endpoint}"/a\        \n        # Add force_refresh parameter if requested\n        if force_refresh and "?" not in url:\n            url += "?force_refresh=true"\n        elif force_refresh:\n            url += "&force_refresh=true"' dashboard.py

# 3. Add POST request function
cat >> dashboard.py << 'POST_FUNCTION'

def make_post_request(endpoint: str, timeout: int = 30) -> Dict[str, Any]:
    """Make POST API request with error handling"""
    try:
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        url = f"{API_BASE_URL}{endpoint}"
        response = requests.post(url, headers=headers, timeout=timeout)
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.Timeout:
        st.error("API request timed out")
        return None
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to API server. Is it running?")
        return None
    except Exception as e:
        st.error(f"API Request Error: {str(e)}")
        return None

POST_FUNCTION

# 4. Update render_header function
sed -i 's/def render_header(api_status: bool, collection_time: str = None):/def render_header(api_status: bool, collection_time: str = None, force_refresh: bool = False):/' dashboard.py

# 5. Add cache status to render_header
sed -i '/status_text = "Connected" if api_status else "Disconnected"/a\    \n    # Add cache status indicator\n    cache_status = "🔄 Fresh Data" if force_refresh else "💾 Cached Data"\n    cache_color = "#00ff88" if force_refresh else "#00ccff"' dashboard.py

# 6. Update the header HTML to include cache status
sed -i 's/<div style="color: #000; font-weight: 500;">/<div style="display: flex; align-items: center; gap: 1rem;">\n                <div style="color: {cache_color}; font-weight: 600; font-size: 0.9rem;">\n                    {cache_status}\n                </div>\n                <div style="color: #000; font-weight: 500;">/' dashboard.py

# 7. Update main function to handle force refresh
sed -i '/if st.button("🔄 Refresh Data", type="primary"):/a\            st.session_state.force_refresh = True' dashboard.py

# 8. Add force refresh logic before API calls
sed -i '/# Fetch data with loading spinner/a\    \n    # Check if force refresh is needed\n    force_refresh = st.session_state.get('\''force_refresh'\'', False)\n    if force_refresh:\n        st.session_state.force_refresh = False  # Reset flag' dashboard.py

# 9. Update API calls to use force_refresh
sed -i 's/summary_data = make_api_request("\/api\/v1\/real\/threats\/summary")/summary_data = make_api_request("\/api\/v1\/real\/threats\/summary", force_refresh=force_refresh)/' dashboard.py
sed -i 's/real_data = make_api_request("\/api\/v1\/real\/threats\/intelligence")/real_data = make_api_request("\/api\/v1\/real\/threats\/intelligence", force_refresh=force_refresh)/' dashboard.py

# 10. Update render_header call
sed -i 's/render_header(api_status, collection_time)/render_header(api_status, collection_time, force_refresh)/' dashboard.py

# 11. Add clear cache button
sed -i '/with col2:/a\    \n    with col3:\n        if st.button("🗑️ Clear Cache", help="Clear cached data to force fresh scraping"):\n            # Clear cache via API\n            result = make_post_request("\/api\/v1\/real\/clear-cache")\n            if result:\n                st.success("Cache cleared successfully!")\n                st.session_state.last_refresh = current_time\n                st.session_state.force_refresh = True\n                st.rerun()\n            else:\n                st.error("Failed to clear cache")' dashboard.py

echo "Dashboard fixes applied successfully!"
