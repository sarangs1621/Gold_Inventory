import React, { useState, useEffect, useCallback } from 'react';
import { API } from '../contexts/AuthContext';
import { formatDateTime, formatDate } from '../utils/dateTimeUtils';
import { safeToFixed, formatCurrency, formatWeight } from '../utils/numberFormat';
import Pagination from '../components/Pagination';
import useURLPagination from '../hooks/useURLPagination';

const ReturnsPage = () => {
  const [returns, setReturns] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Pagination
  const { currentPage, setPage, pagination, setPagination } = useURLPagination();
  const pageSize = 10;
  
  // Filters
  const [filters, setFilters] = useState({
    return_type: '',
    status: '',
    refund_mode: '',
    search: ''
  });
  
  // Dialog states
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showViewDialog, setShowViewDialog] = useState(false);
  const [showFinalizeDialog, setShowFinalizeDialog] = useState(false);
  const [selectedReturn, setSelectedReturn] = useState(null);
  const [finalizeImpact, setFinalizeImpact] = useState(null);
  
  // Create/Edit form state
  const [formData, setFormData] = useState({
    return_type: 'sale_return',
    reference_type: 'invoice',
    reference_id: '',
    items: [{ description: '', qty: 1, weight_grams: 0, purity: 916, amount: 0 }],
    reason: '',
    refund_mode: 'money',
    refund_money_amount: 0,
    refund_gold_grams: 0,
    refund_gold_purity: 916,
    payment_mode: 'cash',
    account_id: '',
    notes: ''
  });
  
  // Reference data (invoices, purchases, accounts)
  const [invoices, setInvoices] = useState([]);
  const [purchases, setPurchases] = useState([]);
  const [accounts, setAccounts] = useState([]);
  
  // Load returns data
  const loadReturns = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = {
        page: currentPage,
        page_size: pageSize,
        ...filters
      };
      
      // Remove empty filters
      Object.keys(params).forEach(key => {
        if (params[key] === '') delete params[key];
      });
      
      const response = await API.get('/api/returns', { params });
      
      setReturns(response.data.items || []);
      setPagination(response.data.pagination);
      setError(''); // Clear any previous errors on successful load
    } catch (err) {
      console.error('Error loading returns:', err);
      setError(err.response?.data?.detail || 'Failed to load returns');
    } finally {
      setLoading(false);
    }
  }, [currentPage, filters, setPagination]);
  
  useEffect(() => {
    loadReturns();
  }, [loadReturns]);
  
  // Load reference data
  const loadReferenceData = async (returnType = 'sale_return') => {
    try {
      // Load returnable invoices based on return type
      if (returnType === 'sale_return') {
        const invoicesRes = await API.get('/api/invoices/returnable', {
          params: { type: 'sales' }
        });
        setInvoices(invoicesRes.data || []);
      } else if (returnType === 'purchase_return') {
        const purchasesRes = await API.get('/api/purchases', {
          params: { page: 1, page_size: 100, status: 'finalized' }
        });
        setPurchases(purchasesRes.data.items || []);
      }
      
      // Load accounts
      const accountsRes = await API.get('/api/accounts');
      setAccounts(accountsRes.data.items || accountsRes.data || []);
    } catch (err) {
      console.error('Error loading reference data:', err);
      setError(err.response?.data?.detail || 'Failed to load reference data');
    }
  };
  
  // Handle filter change
  const handleFilterChange = (field, value) => {
    setFilters(prev => ({ ...prev, [field]: value }));
  };
  
  // Handle form change
  const handleFormChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };
  
  // Handle item change
  const handleItemChange = (index, field, value) => {
    const updatedItems = [...formData.items];
    updatedItems[index][field] = value;
    setFormData(prev => ({ ...prev, items: updatedItems }));
  };
  
  // Add item
  const addItem = () => {
    setFormData(prev => ({
      ...prev,
      items: [...prev.items, { description: '', qty: 1, weight_grams: 0, purity: 916, amount: 0 }]
    }));
  };
  
  // Remove item
  const removeItem = (index) => {
    if (formData.items.length > 1) {
      const updatedItems = formData.items.filter((_, i) => i !== index);
      setFormData(prev => ({ ...prev, items: updatedItems }));
    }
  };
  
  // Open create dialog
  const openCreateDialog = () => {
    loadReferenceData('sale_return');
    setFormData({
      return_type: 'sale_return',
      reference_type: 'invoice',
      reference_id: '',
      items: [{ description: '', qty: 1, weight_grams: 0, purity: 916, amount: 0 }],
      reason: '',
      refund_mode: 'money',
      refund_money_amount: 0,
      refund_gold_grams: 0,
      refund_gold_purity: 916,
      payment_mode: 'cash',
      account_id: '',
      notes: ''
    });
    setShowCreateDialog(true);
    setError('');
    setSuccess('');
  };
  
  // Close create dialog
  const closeCreateDialog = () => {
    setShowCreateDialog(false);
    setFormData({
      return_type: 'sale_return',
      reference_type: 'invoice',
      reference_id: '',
      items: [{ description: '', qty: 1, weight_grams: 0, purity: 916, amount: 0 }],
      reason: '',
      refund_mode: 'money',
      refund_money_amount: 0,
      refund_gold_grams: 0,
      refund_gold_purity: 916,
      payment_mode: 'cash',
      account_id: '',
      notes: ''
    });
  };
  
  // Create return
  const handleCreateReturn = async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      // Validate
      if (!formData.reference_id) {
        setError('Please select a reference invoice or purchase');
        setLoading(false);
        return;
      }
      
      if (formData.items.length === 0 || !formData.items[0].description) {
        setError('Please add at least one item');
        setLoading(false);
        return;
      }
      
      if (formData.refund_mode === 'money' && (!formData.refund_money_amount || formData.refund_money_amount <= 0)) {
        setError('Please enter refund money amount');
        setLoading(false);
        return;
      }
      
      if (formData.refund_mode === 'gold' && (!formData.refund_gold_grams || formData.refund_gold_grams <= 0)) {
        setError('Please enter refund gold amount');
        setLoading(false);
        return;
      }
      
      if (formData.refund_mode === 'mixed' && (!formData.refund_money_amount || formData.refund_money_amount <= 0 || !formData.refund_gold_grams || formData.refund_gold_grams <= 0)) {
        setError('Please enter both refund money and gold amounts for mixed refund');
        setLoading(false);
        return;
      }
      
      if ((formData.refund_mode === 'money' || formData.refund_mode === 'mixed') && !formData.account_id) {
        setError('Please select an account for money refund');
        setLoading(false);
        return;
      }
      
      // Create return
      await API.post('/api/returns', formData);
      
      setSuccess('Return created successfully');
      closeCreateDialog();
      loadReturns();
    } catch (err) {
      console.error('Error creating return:', err);
      setError(err.response?.data?.detail || 'Failed to create return');
    } finally {
      setLoading(false);
    }
  };
  
  // View return
  const viewReturn = async (returnId) => {
    try {
      const response = await API.get(`/api/returns/${returnId}`);
      setSelectedReturn(response.data);
      setShowViewDialog(true);
    } catch (err) {
      console.error('Error fetching return:', err);
      setError(err.response?.data?.detail || 'Failed to load return details');
    }
  };
  
  // Open finalize dialog
  const openFinalizeDialog = async (returnObj) => {
    try {
      // Fetch finalize impact
      const response = await API.get(`/api/returns/${returnObj.id}/finalize-impact`);
      setFinalizeImpact(response.data);
      setSelectedReturn(returnObj);
      setShowFinalizeDialog(true);
    } catch (err) {
      console.error('Error fetching finalize impact:', err);
      setError(err.response?.data?.detail || 'Failed to load finalize impact');
    }
  };
  
  // Finalize return
  const handleFinalizeReturn = async () => {
    if (!selectedReturn) return;
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      await API.post(`/api/returns/${selectedReturn.id}/finalize`);
      setSuccess('Return finalized successfully');
      setShowFinalizeDialog(false);
      setSelectedReturn(null);
      setFinalizeImpact(null);
      loadReturns();
    } catch (err) {
      console.error('Error finalizing return:', err);
      setError(err.response?.data?.detail || 'Failed to finalize return');
    } finally {
      setLoading(false);
    }
  };
  
  // Delete return
  const handleDeleteReturn = async (returnId) => {
    if (!window.confirm('Are you sure you want to delete this return? This action cannot be undone.')) {
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      await API.delete(`/api/returns/${returnId}`);
      setSuccess('Return deleted successfully');
      loadReturns();
    } catch (err) {
      console.error('Error deleting return:', err);
      setError(err.response?.data?.detail || 'Failed to delete return');
    } finally {
      setLoading(false);
    }
  };
  
  // Get status badge
  const getStatusBadge = (status) => {
    const badges = {
      draft: 'bg-yellow-100 text-yellow-800',
      finalized: 'bg-green-100 text-green-800'
    };
    return badges[status] || 'bg-gray-100 text-gray-800';
  };
  
  // Get return type badge
  const getReturnTypeBadge = (type) => {
    const badges = {
      sale_return: 'bg-blue-100 text-blue-800',
      purchase_return: 'bg-purple-100 text-purple-800'
    };
    return badges[type] || 'bg-gray-100 text-gray-800';
  };
  
  // Get refund mode badge
  const getRefundModeBadge = (mode) => {
    const badges = {
      money: 'bg-green-100 text-green-800',
      gold: 'bg-yellow-100 text-yellow-800',
      mixed: 'bg-orange-100 text-orange-800'
    };
    return badges[mode] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-800">Returns Management</h1>
          <p className="text-gray-600 text-sm mt-1">Manage sales and purchase returns</p>
        </div>
        <button
          onClick={openCreateDialog}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
        >
          + Create Return
        </button>
      </div>

      {/* Error/Success Messages */}
      {error && (
        <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-4">
          <p className="text-red-700">{error}</p>
        </div>
      )}
      {success && (
        <div className="bg-green-50 border-l-4 border-green-500 p-4 mb-4">
          <p className="text-green-700">{success}</p>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm p-4 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Return Type</label>
            <select
              value={filters.return_type}
              onChange={(e) => handleFilterChange('return_type', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Types</option>
              <option value="sale_return">Sales Return</option>
              <option value="purchase_return">Purchase Return</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Status</option>
              <option value="draft">Draft</option>
              <option value="finalized">Finalized</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Refund Mode</label>
            <select
              value={filters.refund_mode}
              onChange={(e) => handleFilterChange('refund_mode', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Modes</option>
              <option value="money">Money</option>
              <option value="gold">Gold</option>
              <option value="mixed">Mixed</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
            <input
              type="text"
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
              placeholder="Return #, Party, Reason..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
      </div>

      {/* Returns Table */}
      <div className="bg-white rounded-lg shadow-sm overflow-hidden">
        {loading && !returns.length ? (
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <p className="text-gray-600 mt-2">Loading returns...</p>
          </div>
        ) : returns.length === 0 ? (
          <div className="text-center py-12">
            <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <h3 className="mt-2 text-sm font-medium text-gray-900">No returns found</h3>
            <p className="mt-1 text-sm text-gray-500">Get started by creating a new return.</p>
          </div>
        ) : (
          <>
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Return #</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Party</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reference</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Refund Mode</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount/Weight</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {returns.map((returnObj) => (
                  <tr key={returnObj.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {returnObj.return_number}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getReturnTypeBadge(returnObj.return_type)}`}>
                        {returnObj.return_type === 'sale_return' ? 'Sales' : 'Purchase'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {returnObj.party_name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {returnObj.reference_number || returnObj.reference_id.substring(0, 8)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getRefundModeBadge(returnObj.refund_mode)}`}>
                        {returnObj.refund_mode}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {returnObj.refund_mode === 'money' && `${formatCurrency(returnObj.refund_money_amount)} OMR`}
                      {returnObj.refund_mode === 'gold' && `${formatWeight(returnObj.refund_gold_grams)}g`}
                      {returnObj.refund_mode === 'mixed' && (
                        <div>
                          <div>{formatCurrency(returnObj.refund_money_amount)} OMR</div>
                          <div className="text-xs text-gray-500">{formatWeight(returnObj.refund_gold_grams)}g</div>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusBadge(returnObj.status)}`}>
                        {returnObj.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {formatDate(returnObj.date)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <button
                        onClick={() => viewReturn(returnObj.id)}
                        className="text-blue-600 hover:text-blue-900 mr-3"
                      >
                        View
                      </button>
                      {returnObj.status === 'draft' && (
                        <>
                          <button
                            onClick={() => openFinalizeDialog(returnObj)}
                            className="text-green-600 hover:text-green-900 mr-3"
                          >
                            Finalize
                          </button>
                          <button
                            onClick={() => handleDeleteReturn(returnObj.id)}
                            className="text-red-600 hover:text-red-900"
                          >
                            Delete
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            
            {/* Pagination */}
            {pagination && (
              <div className="px-6 py-4 border-t border-gray-200">
                <Pagination
                  pagination={pagination}
                  onPageChange={setPage}
                />
              </div>
            )}
          </>
        )}
      </div>

      {/* Create Return Dialog */}
      {showCreateDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4">
              <h2 className="text-xl font-semibold text-gray-800">Create New Return</h2>
            </div>
            
            <div className="px-6 py-4 space-y-4">
              {/* Return Type */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Return Type *</label>
                  <select
                    value={formData.return_type}
                    onChange={(e) => {
                      const newReturnType = e.target.value;
                      handleFormChange('return_type', newReturnType);
                      handleFormChange('reference_type', newReturnType === 'sale_return' ? 'invoice' : 'purchase');
                      handleFormChange('reference_id', '');
                      // Reload reference data based on new return type
                      loadReferenceData(newReturnType);
                    }}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="sale_return">Sales Return</option>
                    <option value="purchase_return">Purchase Return</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    {formData.return_type === 'sale_return' ? 'Select Invoice *' : 'Select Purchase *'}
                  </label>
                  <select
                    value={formData.reference_id}
                    onChange={(e) => handleFormChange('reference_id', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    disabled={formData.return_type === 'sale_return' ? invoices.length === 0 : purchases.length === 0}
                  >
                    <option value="">-- Select --</option>
                    {formData.return_type === 'sale_return' ? (
                      invoices.length > 0 ? (
                        invoices.map(inv => (
                          <option key={inv.id} value={inv.id}>
                            {inv.invoice_no} - {inv.party_name} - {formatCurrency(inv.total_amount)} OMR
                          </option>
                        ))
                      ) : null
                    ) : (
                      purchases.map(pur => (
                        <option key={pur.id} value={pur.id}>
                          {pur.id.substring(0, 8)} - {pur.description} - {formatCurrency(pur.amount_total)} OMR
                        </option>
                      ))
                    )}
                  </select>
                  {formData.return_type === 'sale_return' && invoices.length === 0 ? (
                    <p className="text-xs text-red-600 mt-1">
                      ⚠️ No finalized or paid invoices available for return
                    </p>
                  ) : (
                    <p className="text-xs text-gray-500 mt-1">
                      ℹ️ Only finalized or paid {formData.return_type === 'sale_return' ? 'invoices' : 'purchases'} are shown. Draft items cannot be returned.
                    </p>
                  )}
                </div>
              </div>
              
              {/* Items */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Return Items *</label>
                {formData.items.map((item, index) => (
                  <div key={index} className="border border-gray-300 rounded-md p-4 mb-3">
                    <div className="grid grid-cols-5 gap-3 mb-2">
                      <div className="col-span-2">
                        <label className="block text-xs text-gray-600 mb-1">Description</label>
                        <input
                          type="text"
                          value={item.description}
                          onChange={(e) => handleItemChange(index, 'description', e.target.value)}
                          className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                          placeholder="Item description"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-600 mb-1">Qty</label>
                        <input
                          type="number"
                          value={item.qty}
                          onChange={(e) => handleItemChange(index, 'qty', parseInt(e.target.value) || 0)}
                          className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                          min="1"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-600 mb-1">Weight (g)</label>
                        <input
                          type="number"
                          step="0.001"
                          value={item.weight_grams}
                          onChange={(e) => handleItemChange(index, 'weight_grams', parseFloat(e.target.value) || 0)}
                          className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                          min="0"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-600 mb-1">Purity</label>
                        <input
                          type="number"
                          value={item.purity}
                          onChange={(e) => handleItemChange(index, 'purity', parseInt(e.target.value) || 916)}
                          className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                          min="1"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-5 gap-3">
                      <div className="col-span-2">
                        <label className="block text-xs text-gray-600 mb-1">Amount (OMR)</label>
                        <input
                          type="number"
                          step="0.01"
                          value={item.amount}
                          onChange={(e) => handleItemChange(index, 'amount', parseFloat(e.target.value) || 0)}
                          className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                          min="0"
                        />
                      </div>
                      <div className="col-span-3 flex items-end">
                        {formData.items.length > 1 && (
                          <button
                            type="button"
                            onClick={() => removeItem(index)}
                            className="px-3 py-1 text-sm text-red-600 hover:text-red-800 hover:bg-red-50 rounded"
                          >
                            Remove Item
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={addItem}
                  className="text-sm text-blue-600 hover:text-blue-800"
                >
                  + Add Another Item
                </button>
              </div>
              
              {/* Refund Details */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Refund Mode *</label>
                <div className="grid grid-cols-3 gap-2 mb-4">
                  <button
                    type="button"
                    data-testid="refund-mode-money-btn"
                    onClick={() => handleFormChange('refund_mode', 'money')}
                    className={`px-4 py-2 rounded-md font-medium transition-colors ${
                      formData.refund_mode === 'money'
                        ? 'bg-green-600 text-white'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                  >
                    Money Only
                  </button>
                  <button
                    type="button"
                    data-testid="refund-mode-gold-btn"
                    onClick={() => handleFormChange('refund_mode', 'gold')}
                    className={`px-4 py-2 rounded-md font-medium transition-colors ${
                      formData.refund_mode === 'gold'
                        ? 'bg-yellow-600 text-white'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                  >
                    Gold Only
                  </button>
                  <button
                    type="button"
                    data-testid="refund-mode-mixed-btn"
                    onClick={() => handleFormChange('refund_mode', 'mixed')}
                    className={`px-4 py-2 rounded-md font-medium transition-colors ${
                      formData.refund_mode === 'mixed'
                        ? 'bg-orange-600 text-white'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                  >
                    Mixed (Both)
                  </button>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  {(formData.refund_mode === 'money' || formData.refund_mode === 'mixed') && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Money Amount (OMR) *
                        </label>
                        <input
                          data-testid="refund-money-amount-input"
                          type="number"
                          step="0.01"
                          value={formData.refund_money_amount}
                          onChange={(e) => handleFormChange('refund_money_amount', parseFloat(e.target.value) || 0)}
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                          min="0"
                          required={formData.refund_mode === 'money' || formData.refund_mode === 'mixed'}
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Account *</label>
                        <select
                          data-testid="refund-account-select"
                          value={formData.account_id}
                          onChange={(e) => handleFormChange('account_id', e.target.value)}
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                          required={formData.refund_mode === 'money' || formData.refund_mode === 'mixed'}
                        >
                          <option value="">-- Select Account --</option>
                          {accounts.map(acc => (
                            <option key={acc.id} value={acc.id}>
                              {acc.name} ({acc.account_type})
                            </option>
                          ))}
                        </select>
                      </div>
                    </>
                  )}
                  
                  {(formData.refund_mode === 'gold' || formData.refund_mode === 'mixed') && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Gold Weight (g) *
                        </label>
                        <input
                          data-testid="refund-gold-weight-input"
                          type="number"
                          step="0.001"
                          value={formData.refund_gold_grams}
                          onChange={(e) => handleFormChange('refund_gold_grams', parseFloat(e.target.value) || 0)}
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                          min="0"
                          required={formData.refund_mode === 'gold' || formData.refund_mode === 'mixed'}
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Gold Purity</label>
                        <input
                          data-testid="refund-gold-purity-input"
                          type="number"
                          value={formData.refund_gold_purity}
                          onChange={(e) => handleFormChange('refund_gold_purity', parseInt(e.target.value) || 916)}
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                          min="1"
                        />
                      </div>
                    </>
                  )}
                </div>
                
                {formData.refund_mode === 'mixed' && (
                  <div className="mt-2 p-3 bg-blue-50 border border-blue-200 rounded-md">
                    <p className="text-sm text-blue-800">
                      💡 <strong>Mixed Refund:</strong> Both money and gold amounts are required. Total refund value must match return amount.
                    </p>
                  </div>
                )}
                
                {(formData.refund_mode === 'money' || formData.refund_mode === 'mixed') && (
                  <div className="mt-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Payment Mode</label>
                    <select
                      data-testid="refund-payment-mode-select"
                      value={formData.payment_mode}
                      onChange={(e) => handleFormChange('payment_mode', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="cash">Cash</option>
                      <option value="bank_transfer">Bank Transfer</option>
                      <option value="card">Card</option>
                      <option value="upi">UPI</option>
                      <option value="cheque">Cheque</option>
                    </select>
                  </div>
                )}
              </div>
              
              {/* Reason and Notes */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Return Reason</label>
                  <textarea
                    value={formData.reason}
                    onChange={(e) => handleFormChange('reason', e.target.value)}
                    rows="3"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Why is this item being returned?"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Notes</label>
                  <textarea
                    value={formData.notes}
                    onChange={(e) => handleFormChange('notes', e.target.value)}
                    rows="3"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Additional notes"
                  />
                </div>
              </div>
            </div>
            
            <div className="sticky bottom-0 bg-gray-50 px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
              <button
                onClick={closeCreateDialog}
                className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                disabled={loading}
              >
                Cancel
              </button>
              <button
                onClick={handleCreateReturn}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-400"
                disabled={loading}
              >
                {loading ? 'Creating...' : 'Create Return'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Return Dialog */}
      {showViewDialog && selectedReturn && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4">
              <h2 className="text-xl font-semibold text-gray-800">Return Details</h2>
            </div>
            
            <div className="px-6 py-4 space-y-4">
              {/* Return Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-500">Return Number</label>
                  <p className="text-gray-900">{selectedReturn.return_number}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Status</label>
                  <p>
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusBadge(selectedReturn.status)}`}>
                      {selectedReturn.status}
                    </span>
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Return Type</label>
                  <p>
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getReturnTypeBadge(selectedReturn.return_type)}`}>
                      {selectedReturn.return_type === 'sale_return' ? 'Sales Return' : 'Purchase Return'}
                    </span>
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Party</label>
                  <p className="text-gray-900">{selectedReturn.party_name}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Date</label>
                  <p className="text-gray-900">{formatDateTime(selectedReturn.date)}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Reference</label>
                  <p className="text-gray-900">{selectedReturn.reference_number || selectedReturn.reference_id.substring(0, 8)}</p>
                </div>
              </div>
              
              {/* Items */}
              <div>
                <label className="text-sm font-medium text-gray-700 mb-2 block">Return Items</label>
                <div className="border border-gray-200 rounded-md overflow-hidden">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500">Description</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500">Qty</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500">Weight</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500">Purity</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500">Amount</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {selectedReturn.items.map((item, idx) => (
                        <tr key={idx}>
                          <td className="px-4 py-2 text-sm text-gray-900">{item.description}</td>
                          <td className="px-4 py-2 text-sm text-gray-900">{item.qty}</td>
                          <td className="px-4 py-2 text-sm text-gray-900">{formatWeight(item.weight_grams)}g</td>
                          <td className="px-4 py-2 text-sm text-gray-900">{item.purity}</td>
                          <td className="px-4 py-2 text-sm text-gray-900">{formatCurrency(item.amount)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              
              {/* Refund Details */}
              <div className="border-t pt-4">
                <label className="text-sm font-medium text-gray-700 mb-2 block">Refund Details</label>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-500">Refund Mode</label>
                    <p>
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getRefundModeBadge(selectedReturn.refund_mode)}`}>
                        {selectedReturn.refund_mode}
                      </span>
                    </p>
                  </div>
                  {(selectedReturn.refund_mode === 'money' || selectedReturn.refund_mode === 'mixed') && (
                    <>
                      <div>
                        <label className="text-sm font-medium text-gray-500">Money Amount</label>
                        <p className="text-gray-900">{formatCurrency(selectedReturn.refund_money_amount)} OMR</p>
                      </div>
                      <div>
                        <label className="text-sm font-medium text-gray-500">Account</label>
                        <p className="text-gray-900">{selectedReturn.account_name || 'N/A'}</p>
                      </div>
                      <div>
                        <label className="text-sm font-medium text-gray-500">Payment Mode</label>
                        <p className="text-gray-900">{selectedReturn.payment_mode || 'N/A'}</p>
                      </div>
                    </>
                  )}
                  {(selectedReturn.refund_mode === 'gold' || selectedReturn.refund_mode === 'mixed') && (
                    <>
                      <div>
                        <label className="text-sm font-medium text-gray-500">Gold Weight</label>
                        <p className="text-gray-900">{formatWeight(selectedReturn.refund_gold_grams)}g</p>
                      </div>
                      <div>
                        <label className="text-sm font-medium text-gray-500">Gold Purity</label>
                        <p className="text-gray-900">{selectedReturn.refund_gold_purity || 'N/A'}</p>
                      </div>
                    </>
                  )}
                </div>
              </div>
              
              {/* Reason and Notes */}
              {(selectedReturn.reason || selectedReturn.notes) && (
                <div className="border-t pt-4">
                  {selectedReturn.reason && (
                    <div className="mb-3">
                      <label className="text-sm font-medium text-gray-500">Return Reason</label>
                      <p className="text-gray-900">{selectedReturn.reason}</p>
                    </div>
                  )}
                  {selectedReturn.notes && (
                    <div>
                      <label className="text-sm font-medium text-gray-500">Notes</label>
                      <p className="text-gray-900">{selectedReturn.notes}</p>
                    </div>
                  )}
                </div>
              )}
              
              {/* Finalized Details */}
              {selectedReturn.status === 'finalized' && (
                <div className="border-t pt-4">
                  <label className="text-sm font-medium text-gray-700 mb-2 block">Finalization Details</label>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <label className="text-sm font-medium text-gray-500">Finalized At</label>
                      <p className="text-gray-900">{formatDateTime(selectedReturn.finalized_at)}</p>
                    </div>
                    {selectedReturn.transaction_id && (
                      <div>
                        <label className="text-sm font-medium text-gray-500">Transaction ID</label>
                        <p className="text-gray-900 font-mono text-xs">{selectedReturn.transaction_id.substring(0, 16)}...</p>
                      </div>
                    )}
                    {selectedReturn.gold_ledger_id && (
                      <div>
                        <label className="text-sm font-medium text-gray-500">Gold Ledger ID</label>
                        <p className="text-gray-900 font-mono text-xs">{selectedReturn.gold_ledger_id.substring(0, 16)}...</p>
                      </div>
                    )}
                    {selectedReturn.stock_movement_ids && selectedReturn.stock_movement_ids.length > 0 && (
                      <div>
                        <label className="text-sm font-medium text-gray-500">Stock Movements</label>
                        <p className="text-gray-900">{selectedReturn.stock_movement_ids.length} movement(s) created</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            
            <div className="sticky bottom-0 bg-gray-50 px-6 py-4 border-t border-gray-200 flex justify-end">
              <button
                onClick={() => setShowViewDialog(false)}
                className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Finalize Confirmation Dialog */}
      {showFinalizeDialog && finalizeImpact && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-xl font-semibold text-gray-800">Confirm Finalization</h2>
            </div>
            
            <div className="px-6 py-4">
              <div className="mb-4">
                <p className="text-sm text-gray-700 mb-2">
                  <strong>Return:</strong> {finalizeImpact.return_number}
                </p>
                <p className="text-sm text-gray-700 mb-2">
                  <strong>Type:</strong> {finalizeImpact.return_type === 'sale_return' ? 'Sales Return' : 'Purchase Return'}
                </p>
                <p className="text-sm text-gray-700 mb-4">
                  <strong>Party:</strong> {finalizeImpact.party_name}
                </p>
              </div>
              
              <div className="bg-blue-50 border-l-4 border-blue-500 p-4 mb-4">
                <p className="text-sm font-medium text-blue-800 mb-2">Impact Summary:</p>
                <ul className="text-sm text-blue-700 space-y-1">
                  {finalizeImpact.impacts && finalizeImpact.impacts.map((impact, idx) => (
                    <li key={idx}>{impact}</li>
                  ))}
                </ul>
              </div>
              
              <div className="bg-yellow-50 border-l-4 border-yellow-500 p-4">
                <p className="text-sm text-yellow-800">
                  <strong>⚠️ Warning:</strong> {finalizeImpact.warning}
                </p>
              </div>
            </div>
            
            <div className="px-6 py-4 bg-gray-50 border-t border-gray-200 flex justify-end space-x-3">
              <button
                onClick={() => {
                  setShowFinalizeDialog(false);
                  setFinalizeImpact(null);
                  setSelectedReturn(null);
                }}
                className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                disabled={loading}
              >
                Cancel
              </button>
              <button
                onClick={handleFinalizeReturn}
                className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:bg-gray-400"
                disabled={loading || !finalizeImpact.can_proceed}
              >
                {loading ? 'Finalizing...' : 'Confirm Finalize'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReturnsPage;
