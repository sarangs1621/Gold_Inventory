import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';


/**
 * Generate Professional Gold ERP Invoice PDF
 * ENHANCED VERSION - Full Audit Trail with Calculation Transparency
 * 
 * Features:
 * - Complete header with shop and customer details
 * - Detailed item breakdown with all charges
 * - Full calculation summary with formulas
 * - Payment history and status
 * - Draft/Final watermarks
 * - Professional formatting for audit compliance
 */
export const generateProfessionalInvoicePDF = (invoiceData, shopSettings, payments = []) => {
  try {
    const { invoice } = invoiceData;
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    
    // Determine invoice status for watermark
    const isDraft = !invoice.status || invoice.status === 'draft';
    const isFinalized = invoice.status === 'finalized';
    
    // Add watermark for draft invoices
    if (isDraft) {
      doc.setFontSize(60);
      doc.setTextColor(220, 220, 220);
      doc.setFont(undefined, 'bold');
      doc.text('DRAFT', pageWidth / 2, pageHeight / 2, {
        align: 'center',
        angle: 45
      });
      doc.setTextColor(0, 0, 0); // Reset to black
    }
    
    // Add "FINAL INVOICE" badge for finalized invoices
    if (isFinalized) {
      doc.setFontSize(12);
      doc.setTextColor(0, 128, 0);
      doc.setFont(undefined, 'bold');
      doc.text('✓ FINAL INVOICE', pageWidth - 15, 15, { align: 'right' });
      doc.setTextColor(0, 0, 0); // Reset to black
    }
    
    // ============================================================================
    // HEADER SECTION - Company Information
    // ============================================================================
    doc.setFontSize(20);
    doc.setFont(undefined, 'bold');
    doc.text(shopSettings.shop_name || 'Gold Jewellery ERP', 105, 15, { align: 'center' });
    
    doc.setFontSize(9);
    doc.setFont(undefined, 'normal');
    const address = shopSettings.address || '123 Main Street, City, Country';
    doc.text(address, 105, 22, { align: 'center' });
    
    const phone = shopSettings.phone || '+968 1234 5678';
    const email = shopSettings.email || 'contact@shop.com';
    doc.text(`Phone: ${phone} | Email: ${email}`, 105, 27, { align: 'center' });
    
    const gstin = shopSettings.gstin || shopSettings.vat_number || 'N/A';
    if (gstin && gstin !== 'N/A') {
      doc.text(`GST/VAT Number: ${gstin}`, 105, 32, { align: 'center' });
    }
    
    // Horizontal line
    doc.setLineWidth(0.5);
    doc.line(15, gstin !== 'N/A' ? 36 : 32, 195, gstin !== 'N/A' ? 36 : 32);
    
    // ============================================================================
    // INVOICE TITLE
    // ============================================================================
    const titleY = gstin !== 'N/A' ? 45 : 41;
    doc.setFontSize(16);
    doc.setFont(undefined, 'bold');
    doc.text('TAX INVOICE', 105, titleY, { align: 'center' });
    
    // ============================================================================
    // INVOICE METADATA (Enhanced with Customer Type Badge)
    // ============================================================================
    const metaStartY = titleY + 10;
    doc.setFontSize(10);
    
    // Left side - Invoice details
    doc.setFont(undefined, 'bold');
    doc.text('Invoice Number:', 15, metaStartY);
    doc.text('Invoice Date:', 15, metaStartY + 6);
    doc.text('Invoice Type:', 15, metaStartY + 12);
    doc.text('Invoice Status:', 15, metaStartY + 18);
    
    doc.setFont(undefined, 'normal');
    doc.text(invoice.invoice_number || 'N/A', 55, metaStartY);
    doc.text(invoice.date ? new Date(invoice.date).toLocaleDateString() : 'N/A', 55, metaStartY + 6);
    doc.text((invoice.invoice_type || 'sale').toUpperCase(), 55, metaStartY + 12);
    
    // Status with color
    const status = (invoice.status || 'draft').toUpperCase();
    if (status === 'FINALIZED') {
      doc.setTextColor(0, 128, 0);
      doc.setFont(undefined, 'bold');
    }
    doc.text(status, 55, metaStartY + 18);
    doc.setTextColor(0, 0, 0);
    doc.setFont(undefined, 'normal');
    
    // Right side - Customer details
    doc.setFont(undefined, 'bold');
    doc.text('Bill To:', 120, metaStartY);
    doc.setFont(undefined, 'normal');
    
    let customerName = 'Walk-in Customer';
    let customerPhone = '';
    let customerType = invoice.customer_type || 'walk_in';
    
    if (customerType === 'saved') {
      customerName = invoice.customer_name || 'Saved Customer';
      if (invoiceData.customer_details) {
        customerPhone = invoiceData.customer_details.phone || invoice.customer_phone || '';
      } else if (invoice.customer_phone) {
        customerPhone = invoice.customer_phone;
      }
    } else {
      customerName = invoice.walk_in_name || 'Walk-in Customer';
      customerPhone = invoice.walk_in_phone || '';
    }
    
    doc.setFont(undefined, 'bold');
    doc.text(customerName, 120, metaStartY + 6);
    doc.setFont(undefined, 'normal');
    
    // Customer type badge
    if (customerType === 'walk_in') {
      doc.setFontSize(8);
      doc.setTextColor(180, 100, 0);
      doc.text('[WALK-IN CUSTOMER]', 120, metaStartY + 11);
      doc.setTextColor(0, 0, 0);
      doc.setFontSize(10);
    }
    
    if (customerPhone) {
      doc.text(`Phone: ${customerPhone}`, 120, metaStartY + 16);
    }
    
    // ============================================================================
    // ITEMS TABLE - Comprehensive Gold Jewellery Breakdown
    // ============================================================================
    const tableStartY = metaStartY + 30;
    
    // Enhanced table headers with all required columns
    const tableHeaders = [
      'Category',
      'Description', 
      'Qty',
      'Purity',
      'Weight(g)',
      'Gold Rate',
      'Gold Value',
      'Making',
      'VAT %',
      'VAT Amt',
      'Line Total'
    ];
    
    const tableData = (invoice.items || []).map(item => {
      const weight = item.net_gold_weight || item.weight || 0;
      const purity = item.purity || 916;
      const goldRate = item.metal_rate || 0;
      const goldValue = item.gold_value || (weight * goldRate);
      const making = item.making_value || 0;
      const vatPercent = item.vat_percent || 5;
      const vatAmount = item.vat_amount || 0;
      const lineTotal = item.line_total || 0;
      
      return [
        item.category || '-',
        item.description || '-',
        item.qty || 1,
        `${purity}K`,
        weight.toFixed(3),
        goldRate.toFixed(3),
        goldValue.toFixed(3),
        making.toFixed(3),
        `${vatPercent}%`,
        vatAmount.toFixed(3),
        lineTotal.toFixed(3)
      ];
    });
    
    autoTable(doc, {
      startY: tableStartY,
      head: [tableHeaders],
      body: tableData,
      theme: 'grid',
      headStyles: { 
        fillColor: [41, 128, 185],
        fontSize: 8,
        fontStyle: 'bold',
        halign: 'center',
        cellPadding: 2
      },
      bodyStyles: { 
        fontSize: 8,
        cellPadding: 2
      },
      columnStyles: {
        0: { cellWidth: 22, halign: 'left' },    // Category
        1: { cellWidth: 32, halign: 'left' },    // Description
        2: { cellWidth: 10, halign: 'center' },  // Qty
        3: { cellWidth: 14, halign: 'center' },  // Purity
        4: { cellWidth: 16, halign: 'right' },   // Weight
        5: { cellWidth: 16, halign: 'right' },   // Gold Rate
        6: { cellWidth: 18, halign: 'right' },   // Gold Value
        7: { cellWidth: 16, halign: 'right' },   // Making
        8: { cellWidth: 12, halign: 'center' },  // VAT %
        9: { cellWidth: 16, halign: 'right' },   // VAT Amt
        10: { cellWidth: 18, halign: 'right' }   // Line Total
      },
      margin: { left: 10, right: 10 }
    });
    
    // ============================================================================
    // CALCULATION SUMMARY - Full Transparency with Formulas
    // ============================================================================
    let currentY = doc.lastAutoTable.finalY + 10;
    const leftCol = 15;
    const rightCol = 195;
    
    // Add calculation header
    doc.setFontSize(11);
    doc.setFont(undefined, 'bold');
    doc.text('CALCULATION SUMMARY', leftCol, currentY);
    
    currentY += 8;
    doc.setFontSize(9);
    doc.setFont(undefined, 'normal');
    
    // Calculate component totals
    const items = invoice.items || [];
    const metalTotal = items.reduce((sum, item) => sum + (item.gold_value || 0), 0);
    const makingTotal = items.reduce((sum, item) => sum + (item.making_value || 0), 0);
    const totalWeight = items.reduce((sum, item) => sum + (item.weight || item.net_gold_weight || 0), 0);
    
    // Metal Total with formula
    doc.setFont(undefined, 'bold');
    doc.text('Metal Total:', leftCol + 5, currentY);
    doc.setFont(undefined, 'normal');
    doc.text(`Weight × Gold Rate`, leftCol + 40, currentY);
    doc.setFont(undefined, 'bold');
    doc.text(`${metalTotal.toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    
    currentY += 5;
    doc.setFontSize(8);
    doc.setFont(undefined, 'italic');
    doc.setTextColor(80, 80, 80);
    doc.text(`(${totalWeight.toFixed(3)}g total weight)`, leftCol + 10, currentY);
    doc.setTextColor(0, 0, 0);
    
    // Making Charges Total
    currentY += 5;
    doc.setFontSize(9);
    doc.setFont(undefined, 'bold');
    doc.text('Making Charges Total:', leftCol + 5, currentY);
    doc.text(`${makingTotal.toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    
    // Subtotal calculation
    currentY += 7;
    const subtotal = invoice.subtotal || (metalTotal + makingTotal);
    doc.setFont(undefined, 'bold');
    doc.text('Subtotal:', leftCol, currentY);
    doc.setFont(undefined, 'normal');
    doc.text(`Metal + Making`, leftCol + 35, currentY);
    doc.setFont(undefined, 'bold');
    doc.text(`${subtotal.toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    
    // Invoice-level discount (if any)
    const invoiceDiscount = invoice.discount_amount || 0;
    if (invoiceDiscount > 0) {
      currentY += 6;
      doc.setFont(undefined, 'bold');
      doc.setTextColor(200, 0, 0);
      doc.text('Invoice Discount:', leftCol + 5, currentY);
      doc.text(`-${invoiceDiscount.toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
      doc.setTextColor(0, 0, 0);
    }
    
    // VAT Calculation
    currentY += 7;
    const vatTotal = invoice.vat_total || 0;
    const vatPercent = items.length > 0 ? (items[0].vat_percent || 5) : 5;
    doc.setFont(undefined, 'bold');
    doc.text(`VAT (${vatPercent}%):`, leftCol, currentY);
    doc.setFont(undefined, 'normal');
    doc.text(`Subtotal × ${vatPercent}%`, leftCol + 35, currentY);
    doc.setFont(undefined, 'bold');
    doc.text(`${vatTotal.toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    
    // Round off (if any)
    const roundOff = invoice.round_off_amount || 0;
    if (roundOff !== 0 && roundOff !== null) {
      currentY += 6;
      doc.setFont(undefined, 'bold');
      doc.text('Round Off:', leftCol + 5, currentY);
      doc.text(`${roundOff > 0 ? '+' : ''}${roundOff.toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    }
    
    // Grand Total - Highlighted
    currentY += 10;
    doc.setFillColor(41, 128, 185);
    doc.rect(leftCol - 2, currentY - 6, 182, 10, 'F');
    
    doc.setFontSize(12);
    doc.setFont(undefined, 'bold');
    doc.setTextColor(255, 255, 255);
    doc.text('GRAND TOTAL:', leftCol + 3, currentY);
    doc.text(`${(invoice.grand_total || 0).toFixed(3)} OMR`, rightCol - 3, currentY, { align: 'right' });
    doc.setTextColor(0, 0, 0);
    
    currentY += 8;
    doc.setFontSize(8);
    doc.setFont(undefined, 'italic');
    doc.text('All calculations are final after invoice finalization', leftCol, currentY);
    
    // ============================================================================
    // PAYMENT DETAILS SECTION - Enhanced
    // ============================================================================
    currentY += 12;
    
    // Check if we need a new page
    if (currentY > 230) {
      doc.addPage();
      currentY = 20;
    }
    
    doc.setFontSize(11);
    doc.setFont(undefined, 'bold');
    doc.text('PAYMENT DETAILS', leftCol, currentY);
    
    currentY += 8;
    doc.setFontSize(9);
    
    // Payment Status
    const paymentStatus = invoice.payment_status || 'unpaid';
    doc.setFont(undefined, 'bold');
    doc.text('Payment Status:', leftCol + 5, currentY);
    
    // Color code the status
    if (paymentStatus === 'paid') {
      doc.setTextColor(0, 150, 0);
    } else if (paymentStatus === 'partial') {
      doc.setTextColor(200, 100, 0);
    } else {
      doc.setTextColor(200, 0, 0);
    }
    doc.text(paymentStatus.toUpperCase(), rightCol, currentY, { align: 'right' });
    doc.setTextColor(0, 0, 0);
    
    // Payment breakdown table (if payments exist)
    if (payments && payments.length > 0) {
      currentY += 8;
      
      const paymentHeaders = [['Date', 'Payment Mode', 'Amount', 'Notes']];
      const paymentData = payments.map(payment => [
        payment.date ? new Date(payment.date).toLocaleDateString() : 'N/A',
        payment.mode || payment.payment_mode || 'N/A',
        `${(payment.amount || 0).toFixed(3)} OMR`,
        payment.notes || '-'
      ]);
      
      autoTable(doc, {
        startY: currentY,
        head: paymentHeaders,
        body: paymentData,
        theme: 'striped',
        headStyles: { 
          fillColor: [52, 152, 219],
          fontSize: 8,
          fontStyle: 'bold'
        },
        bodyStyles: { fontSize: 8 },
        columnStyles: {
          0: { cellWidth: 30 },
          1: { cellWidth: 35 },
          2: { cellWidth: 30, halign: 'right' },
          3: { cellWidth: 90 }
        },
        margin: { left: 15, right: 15 }
      });
      
      currentY = doc.lastAutoTable.finalY + 8;
    } else {
      currentY += 6;
      doc.setFont(undefined, 'italic');
      doc.setTextColor(120, 120, 120);
      doc.text('No payments recorded yet', leftCol + 5, currentY);
      doc.setTextColor(0, 0, 0);
      currentY += 6;
    }
    
    // Payment summary
    currentY += 4;
    doc.setFont(undefined, 'bold');
    doc.text('Paid Amount:', leftCol + 5, currentY);
    doc.setTextColor(0, 150, 0);
    doc.text(`${(invoice.paid_amount || 0).toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    doc.setTextColor(0, 0, 0);
    
    // Balance due or overpayment
    currentY += 6;
    const balanceDue = invoice.balance_due || 0;
    
    doc.setFont(undefined, 'bold');
    if (balanceDue > 0.001) {
      doc.text('Balance Due:', leftCol + 5, currentY);
      doc.setTextColor(200, 0, 0);
      doc.text(`${balanceDue.toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    } else if (balanceDue < -0.001) {
      doc.text('Overpayment:', leftCol + 5, currentY);
      doc.setTextColor(0, 150, 0);
      doc.text(`${Math.abs(balanceDue).toFixed(3)} OMR`, rightCol, currentY, { align: 'right' });
    } else {
      doc.text('Payment Status:', leftCol + 5, currentY);
      doc.setTextColor(0, 150, 0);
      doc.text('✓ PAID IN FULL', rightCol, currentY, { align: 'right' });
    }
    doc.setTextColor(0, 0, 0);
    
    // ============================================================================
    // FOOTER - Terms, Conditions & Print Info
    // ============================================================================
    currentY += 15;
    
    // Check if we need a new page
    if (currentY > 240) {
      doc.addPage();
      currentY = 20;
    }
    
    doc.setFontSize(9);
    doc.setFont(undefined, 'bold');
    doc.text('Terms & Conditions:', leftCol, currentY);
    
    currentY += 5;
    doc.setFontSize(8);
    doc.setFont(undefined, 'normal');
    const terms = shopSettings.terms_and_conditions || 
      "1. Goods once sold cannot be returned.\n2. Gold purity as per invoice.\n3. Making charges are non-refundable.";
    const termsLines = terms.split('\n');
    termsLines.forEach(line => {
      if (currentY > 270) {
        doc.addPage();
        currentY = 20;
      }
      doc.text(line, leftCol, currentY);
      currentY += 4;
    });
    
    // Print information footer
    currentY += 10;
    if (currentY > 270) {
      doc.addPage();
      currentY = 20;
    }
    
    doc.setFontSize(7);
    doc.setFont(undefined, 'italic');
    doc.setTextColor(100, 100, 100);
    
    // Print timestamp
    const printDate = new Date();
    const printTimestamp = `Printed: ${printDate.toLocaleDateString()} ${printDate.toLocaleTimeString()}`;
    doc.text(printTimestamp, leftCol, currentY);
    
    // Printed by user (if available from invoiceData)
    if (invoiceData.printed_by || invoice.created_by) {
      currentY += 3;
      doc.text(`Printed By: ${invoiceData.printed_by || invoice.created_by}`, leftCol, currentY);
    }
    
    doc.setTextColor(0, 0, 0);
    
    // Authorized signature
    currentY += 10;
    doc.setFontSize(9);
    doc.setFont(undefined, 'normal');
    doc.text('_____________________', rightCol - 40, currentY);
    currentY += 5;
    doc.text(shopSettings.authorized_signatory || 'Authorized Signatory', rightCol - 40, currentY);
    
    // Computer generated note at bottom
    const bottomY = 285;
    doc.setFontSize(7);
    doc.setFont(undefined, 'italic');
    doc.setTextColor(120, 120, 120);
    doc.text('This is a system-generated invoice and is valid without signature', 105, bottomY, { align: 'center' });
    doc.text('All calculations are final after invoice finalization', 105, bottomY + 3, { align: 'center' });
    
    return doc;
  } catch (error) {
    console.error('Error generating professional invoice PDF:', error);
    throw error;
  }
};

/**
 * Download professional invoice PDF
 */
export const downloadProfessionalInvoicePDF = async (invoiceId, apiUrl, axiosInstance) => {
  try {
    // Fetch full invoice details
    const [invoiceResponse, settingsResponse] = await Promise.all([
      axiosInstance.get(`${apiUrl}/invoices/${invoiceId}/full-details`),
      axiosInstance.get(`${apiUrl}/settings/shop`)
    ]);
    
    const invoiceData = invoiceResponse.data;
    const shopSettings = settingsResponse.data;
    
    // Generate PDF
    const doc = generateProfessionalInvoicePDF(invoiceData, shopSettings, invoiceData.payments);
    
    // Download
    doc.save(`Invoice_${invoiceData.invoice.invoice_number || 'unknown'}.pdf`);
    
    return { success: true };
  } catch (error) {
    console.error('Error downloading professional invoice PDF:', error);
    return { success: false, error: error.message };
  }
};
