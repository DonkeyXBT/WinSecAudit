using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinSecAudit.Models;

namespace WinSecAudit.ViewModels;

/// <summary>
/// ViewModel for displaying and filtering findings.
/// </summary>
public partial class FindingsViewModel : ObservableObject
{
    private List<Finding> _allFindings = new();

    [ObservableProperty]
    private List<Finding> _filteredFindings = new();

    [ObservableProperty]
    private Finding? _selectedFinding;

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private Severity? _severityFilter;

    [ObservableProperty]
    private string? _categoryFilter;

    [ObservableProperty]
    private bool _showPassed = false;

    [ObservableProperty]
    private string _sortBy = "Severity";

    [ObservableProperty]
    private bool _sortDescending = true;

    public FindingsViewModel()
    {
    }

    public void LoadFindings(IEnumerable<Finding> findings)
    {
        _allFindings = findings.ToList();
        ApplyFilters();
    }

    [RelayCommand]
    private void ApplyFilters()
    {
        var filtered = _allFindings.AsEnumerable();

        // Filter by severity
        if (SeverityFilter.HasValue)
        {
            filtered = filtered.Where(f => f.Severity == SeverityFilter.Value);
        }

        // Filter out passed if not showing
        if (!ShowPassed)
        {
            filtered = filtered.Where(f => f.Severity != Severity.Passed);
        }

        // Filter by category
        if (!string.IsNullOrEmpty(CategoryFilter))
        {
            filtered = filtered.Where(f => f.Category == CategoryFilter);
        }

        // Search query
        if (!string.IsNullOrEmpty(SearchQuery))
        {
            var query = SearchQuery.ToLower();
            filtered = filtered.Where(f =>
                f.Check.ToLower().Contains(query) ||
                f.Description.ToLower().Contains(query) ||
                f.Details.ToLower().Contains(query));
        }

        // Sort
        filtered = SortBy switch
        {
            "Severity" => SortDescending
                ? filtered.OrderByDescending(f => f.Severity)
                : filtered.OrderBy(f => f.Severity),
            "Category" => SortDescending
                ? filtered.OrderByDescending(f => f.Category)
                : filtered.OrderBy(f => f.Category),
            "Check" => SortDescending
                ? filtered.OrderByDescending(f => f.Check)
                : filtered.OrderBy(f => f.Check),
            _ => filtered
        };

        FilteredFindings = filtered.ToList();
    }

    [RelayCommand]
    private void ClearFilters()
    {
        SearchQuery = string.Empty;
        SeverityFilter = null;
        CategoryFilter = null;
        ShowPassed = false;
        ApplyFilters();
    }

    [RelayCommand]
    private void SelectFinding(Finding finding)
    {
        SelectedFinding = finding;
    }

    partial void OnSearchQueryChanged(string value) => ApplyFilters();
    partial void OnSeverityFilterChanged(Severity? value) => ApplyFilters();
    partial void OnCategoryFilterChanged(string? value) => ApplyFilters();
    partial void OnShowPassedChanged(bool value) => ApplyFilters();
    partial void OnSortByChanged(string value) => ApplyFilters();
    partial void OnSortDescendingChanged(bool value) => ApplyFilters();

    public IEnumerable<string> GetCategories()
    {
        return _allFindings.Select(f => f.Category).Distinct().OrderBy(c => c);
    }

    public Dictionary<Severity, int> GetSeverityCounts()
    {
        return _allFindings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());
    }
}
